#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>
#include <mach-o/loader.h>
#include "kutils.h"
#include "kmem.h"
#include "find_port.h"
#include "symbols.h"

//addresses of various structures.
//from patchfinder64.c by xerub
static uint8_t *kernel = NULL;
static uint64_t xnucore_base = 0;
static uint64_t xnucore_size = 0;
static uint64_t prelink_base = 0;
static uint64_t prelink_size = 0;
static uint64_t cstring_base = 0;
static uint64_t cstring_size = 0;
static uint64_t pstring_base = 0;
static uint64_t pstring_size = 0;
static uint64_t kerndumpbase = -1;
static uint64_t kernel_entry = 0;
static uint64_t kernel_delta = 0;
static size_t kernel_size = 0;
static void *kernel_mh = 0;

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr() {
  if (cached_task_self_addr == 0) {
    cached_task_self_addr = find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
    printf("task self: 0x%llx\n", cached_task_self_addr);
  }
  return cached_task_self_addr;
}

uint64_t ipc_space_kernel() {
  return rk64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

uint64_t current_thread() {
  uint64_t thread_port = find_port_address(mach_thread_self(), MACH_MSG_TYPE_COPY_SEND);
  return rk64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

uint64_t find_kernel_base() {
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  uint64_t base = realhost & ~0xfffULL;
  // walk down to find the magic:
  for (int i = 0; i < 0x10000; i++) {
    if (rk32(base) == 0xfeedfacf) {
      return base;
    }
    base -= 0x1000;
  }
  return 0;
}
mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv() {
  if (fake_host_priv_port != MACH_PORT_NULL) {
    return fake_host_priv_port;
  }
  // get the address of realhost:
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  // allocate a port
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    printf("failed to allocate port\n");
    return MACH_PORT_NULL;
  }
  
  // get a send right
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  // locate the port
  uint64_t port_addr = find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
  
  // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
  wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_HOST_PRIV);
  
  // change the space of the port
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
  
  // set the kobject
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
  
  fake_host_priv_port = port;
  
  return port;
}

// --- Patchfinder functions ------
//from https://github.com/xerub/extra_recipe/blob/master/extra_recipe/patchfinder64.c
#define INSN_RET  0xD65F03C0, 0xFFFFFFFF
#define INSN_CALL 0x94000000, 0xFC000000
#define INSN_B    0x14000000, 0xFC000000
#define INSN_CBZ  0x34000000, 0xFC000000

static uint64_t
step64(const uint8_t *buf, uint64_t start, size_t length, uint32_t what, uint32_t mask)
{
    uint64_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

static uint64_t follow_call64(const uint8_t *buf, uint64_t call)
{
    long long w;
    w = *(uint32_t *)(buf + call) & 0x3FFFFFF;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    return call + w;
}

#define UCHAR_MAX 255

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

mach_port_t tfpzero;

size_t kread(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            fprintf(stderr, "[e] error reading kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, chunk);
        if (rv) {
            fprintf(stderr, "[e] error writing kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

uint64_t kalloc(vm_size_t size){
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

int setupKernelDump(mach_port_t tfp0){
    tfpzero = tfp0;
    
    size_t rv;
    uint8_t buf[0x4000];
    unsigned i, j;
    const struct mach_header *hdr = (struct mach_header *)buf;
    const uint8_t *q;
    uint64_t min = -1;
    uint64_t max = 0;
    int is64 = 4;
    
    uint64_t base = find_kernel_base();
    
    rv = kread(base, buf, sizeof(buf));
    if (rv != sizeof(buf)) {
        return -1;
    }
    
    
    q = buf + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
            if (!strcmp(seg->segname, "__TEXT_EXEC")) {
                xnucore_base = seg->vmaddr;
                xnucore_size = seg->filesize;
                printf("XNUCore: %llx  -- %llx\n",xnucore_base,xnucore_size);
            }
            if (!strcmp(seg->segname, "__PLK_TEXT_EXEC")) {
                prelink_base = seg->vmaddr;
                prelink_size = seg->filesize;
                printf("PLK_TEXT: %llx  -- %llx\n",prelink_base,prelink_size);
            }
            if (!strcmp(seg->segname, "__TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__cstring")) {
                        cstring_base = sec[j].addr;
                        cstring_size = sec[j].size;
                        printf("cstring: %llx  -- %llx\n",cstring_base,cstring_size);
                    }
                }
            }
            if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        pstring_base = sec[j].addr;
                        pstring_size = sec[j].size;
                        printf("__text: %llx  -- %llx\n",pstring_base,pstring_size);
                    }
                }
            }
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                kernel_delta = seg->vmaddr - min - seg->fileoff;
                printf("kernel delta: %llx  -- %llx -- %llx\n",seg->vmaddr,min,seg->fileoff);
            }
        }
        if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint64_t x[29];    /* General purpose registers x0-x28 */
                uint64_t fp;    /* Frame pointer x29 */
                uint64_t lr;    /* Link register x30 */
                uint64_t sp;    /* Stack pointer x31 */
                uint64_t pc;     /* Program counter */
                uint32_t cpsr;    /* Current program status register */
            } *thread = (void *)(ptr + 2);
            if (flavor == 6) {
                kernel_entry = thread->pc;
            }
        }
        q = q + cmd->cmdsize;
    }
    
    kerndumpbase = min;
    xnucore_base -= kerndumpbase;
    prelink_base -= kerndumpbase;
    cstring_base -= kerndumpbase;
    pstring_base -= kerndumpbase;
    kernel_size = max - min;
    
    kernel = malloc(kernel_size);
    rv = kread(kerndumpbase, kernel, kernel_size);
    if (rv != kernel_size) {
        free(kernel);
        return -1;
    }
    
    kernel_mh = kernel + base - min;
    return 0;
}

//find a string inside a array
static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */
    
    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;
    
    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;
    
    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;
    
    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;
    
    /* ---- Do the matching ---- */
    
    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;
        
        /* otherwise, we need to skip some bytes and start again.
         Note that here we are getting the skip value based on the last byte
         of needle, no matter where we didn't match. So if needle is: "abcd"
         then we are skipping based on 'd' and that value will be 4, and
         for "abcdd" we again skip on 'd' but the value will be only 1.
         The alternative of pretending that the mismatched character was
         the last character is slower in the normal case (E.g. finding
         "abcd" in "...azcd..." gives 4 by using 'd' but only
         4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }
    
    return NULL;
}

uint64_t bof64(const uint8_t *buf, uint64_t start, uint64_t where)
{
    for (; where >= start; where -= 4) {
        uint32_t op = *(uint32_t *)(buf + where);
        if ((op & 0xFFC003FF) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xFFF;
            //printf("%x: ADD X29, SP, #0x%x\n", where, delta);
            if ((delta & 0xF) == 0) {
                uint64_t prev = where - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(buf + prev);
                if ((au & 0xFFC003E0) == 0xA98003E0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                }
            }
        }
    }
    return 0;
}

uint64_t calc64(const uint8_t *buf, uint64_t start, uint64_t end, int which)
{
    uint64_t i;
    uint64_t value[32];
    
    memset(value, 0, sizeof(value));
    
    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
             unsigned rd = op & 0x1F;
             unsigned rm = (op >> 16) & 0x1F;
             //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
             value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[rn] = value[rn] + imm;    // XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;        // XXX address, not actual value
        }
    }
    return value[which];
}

uint64_t xref64(const uint8_t *buf, uint64_t start, uint64_t end, uint64_t what)
{
    uint64_t i;
    uint64_t value[32];
    
    memset(value, 0, sizeof(value));
    
    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
             unsigned rd = op & 0x1F;
             unsigned rm = (op >> 16) & 0x1F;
             //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
             value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
            /*} else if ((op & 0xF9C00000) == 0xF9000000) {
             unsigned rn = (op >> 5) & 0x1F;
             unsigned imm = ((op >> 10) & 0xFFF) << 3;
             //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
             if (!imm) continue;            // XXX not counted as true xref
             value[rn] = value[rn] + imm;    // XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;        // XXX address, not actual value
        }
        if (value[reg] == what) {
            return i;
        }
    }
    return 0;
}

uint64_t find_reference(uint64_t to, int n, int prelink)
{
    uint64_t ref, end;
    uint64_t base = xnucore_base;
    uint64_t size = xnucore_size;
    if (prelink) {
        base = prelink_base;
        size = prelink_size;
    }
    if (n <= 0) {
        n = 1;
    }
    end = base + size;
    to -= kerndumpbase;
    do {
        ref = xref64(kernel, base, end, to);
        if (!ref) {
            return 0;
        }
        base = ref + 4;
    } while (--n > 0);
    return ref + kerndumpbase;
}
uint64_t find_allproc(void) {
    // Find the first reference to the string
    uint64_t ref = find_strref("\"pgrp_add : pgrp is dead adding process\"", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, xnucore_base, ref);
    if (!start) {
        return 0;
    }
    
    // Find AND W8, W8, #0xFFFFDFFF - it's a pretty distinct instruction
    uint64_t weird_instruction = 0;
    for (int i = 4; i < 4*0x100; i+=4) {
        uint32_t op = *(uint32_t *)(kernel + ref + i);
        if (op == 0x12127908) {
            weird_instruction = ref+i;
            break;
        }
    }
    if (!weird_instruction) {
        return 0;
    }
    
    uint64_t val = calc64(kernel, start, weird_instruction - 8, 8);
    if (!val) {
        printf("Failed to calculate x8");
        return 0;
    }
    
    return val + kerndumpbase;
}

uint64_t find_strref(const char *string, int n, int prelink){
    uint8_t *str;
    uint64_t base = cstring_base;
    uint64_t size = cstring_size;
    if (prelink) {
        base = pstring_base;
        size = pstring_size;
    }
    str = boyermoore_horspool_memmem(kernel + base, size, (uint8_t *)string, strlen(string));
    if (!str) {
        return 0;
    }
    return find_reference(str - kernel + kerndumpbase, n, prelink);
}

//find location of the rootvnode so we can remount RW
//this calculation was found by @theninjaprawn ; https://github.com/ninjaprawn/async_awake-fun/blob/master/async_wake_ios/the_fun_part/patchfinder64.c
uint64_t find_rootvnode(void) {
    // Find the first reference to the string
    uint64_t ref = find_strref("/var/run/.vfs_rsrc_streams_%p%x", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, xnucore_base, ref);
    if (!start) {
        return 0;
    }
    
    // Find MOV X9, #0x2000000000 - it's a pretty distinct instruction
    uint64_t weird_instruction = 0;
    for (int i = 4; i < 4*0x100; i+=4) {
        uint32_t op = *(uint32_t *)(kernel + ref - i);
        if (op == 0xB25B03E9) {
            weird_instruction = ref-i;
            break;
        }
    }
    if (!weird_instruction) {
        return 0;
    }
    
    uint64_t val = calc64(kernel, start, weird_instruction, 8);
    if (!val) {
        printf("Failed to calculate x8");
        return 0;
    }
    
    return val + kerndumpbase;
}
//find_trustcache by stek29: https://github.com/stek29/async_awake-fun/blob/master/async_wake_ios/the_fun_part/patchfinder64.c#L1147
uint64_t find_trustcache(void) {
    uint64_t call, func, val;
    uint64_t ref = find_strref("com.apple.MobileFileIntegrity", 1, 1);
    if (!ref) {
        printf("didnt find string ref\n");
        return 0;
    }
    ref -= kerndumpbase;
    call = step64(kernel, ref, 32, INSN_CALL);
    if (!call) {
        printf("couldn't find the call\n");
        return 0;
    }
    call = step64(kernel, call+4, 32, INSN_CALL);
    func = follow_call64(kernel, call);
    if (!func) {
        printf("couldn't follow the call\n");
        return 0;
    }
    val = calc64(kernel, func, func + 16, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}
