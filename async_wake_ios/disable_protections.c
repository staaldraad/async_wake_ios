//
//  disable_protections.c
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
#include "disable_protections.h"

void disable_amfid(){
   uint64_t amfid_pid = get_process_pid_from_name("amfid");
    
}
