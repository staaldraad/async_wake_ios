#ifndef kutils_h
#define kutils_h

#include <mach/mach.h>

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);
int setupKernelDump(mach_port_t);
uint64_t find_strref(const char*,int,int);

size_t kread(uint64_t , void*, size_t );
size_t kwrite(uint64_t , const void* , size_t );
uint64_t kalloc(vm_size_t );
uint64_t find_allproc(void);
#endif /* kutils_h */
