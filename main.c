#include <stdio.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "libhook.h"

#define byte uint8_t

#define INTERPRETER_FILE_SIZE 240936

static unsigned char INTERPRETER[INTERPRETER_FILE_SIZE] = "INTERPRETER_HERE";

int main()
{
    printf("Hello world!\n");
    return 0;
}

#define PAGE_SIZE 4096

#define ELF_EXEC_PAGESIZE	4096

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(int)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define min(a, b) a < b ? a : b
#define max(a, b) a > b ? a : b

#define bool int
#define false 0
#define true 1

static unsigned long total_mapping_size(const Elf64_Phdr *phdr, int nr)
{
	uint64_t min_addr = -1;
	uint64_t max_addr = 0;
	bool pt_load = false;
	int i;

	for (i = 0; i < nr; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			min_addr = min(min_addr, ELF_PAGESTART(phdr[i].p_vaddr));
			max_addr = max(max_addr, phdr[i].p_vaddr + phdr[i].p_memsz);
			pt_load = true;
		}
	}
	return pt_load ? (max_addr - min_addr) : 0;
}

void* mmap_custom(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void* result;
    // Inline assembly to perform the syscall
    asm volatile (
        "syscall"
        : "=a" (result)            // Output: result in rax
        : "0" (SYS_mmap),          // Input: syscall number for mmap
          "D" (addr),              // addr (rdi)
          "S" (length),            // length (rsi)
          "d" (prot),              // prot (rdx)
          "r" (fd),             // flags (r10)
          "r" (offset),                // fd (r8)
          "r" (flags)             // offset (r9)
        : "rcx", "r11", "memory"   // Clobbered registers
    );
    return result;
}

static unsigned long elf_map(const unsigned char* elf_buffer, unsigned long addr,
		const Elf64_Phdr *eppnt, int prot, int type,
		unsigned long total_size)
{
	unsigned long map_addr;
	unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
	unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);

	/* mmap() will return -EINVAL if given a zero size, but a
	 * segment with zero filesize is perfectly valid */
	if (!size)
		return addr;

	/*
	* total_size is the size of the ELF (interpreter) image.
	* The _first_ mmap needs to know the full size, otherwise
	* randomization might put this image into an overlapping
	* position with the ELF binary image. (since size < total_size)
	* So we first map the 'big' image - and unmap the remainder at
	* the end. (which unmap is needed for ELF images with holes.)
	*/

    unsigned long mmap_size;
	if (total_size) {
		total_size = ELF_PAGEALIGN(total_size);
        mmap_size = total_size;
	} else {
        mmap_size = size;
    }

    map_addr = mmap_custom((void*)addr, mmap_size, prot, type | MAP_ANONYMOUS, -1, 0);
    for (unsigned long i = 0; i < mmap_size; i++) {
        ((unsigned char*)map_addr)[i] = 0;
    }

    // basically memcpy
    for (unsigned long i = 0; i < mmap_size; i++) {
        if (off + i >= INTERPRETER_FILE_SIZE || i >= eppnt->p_filesz) {
            ((unsigned char*)map_addr)[i] = 0;
            continue;
        }
        ((unsigned char*)map_addr)[i] = elf_buffer[off + i];
    }

	return(map_addr);
}

extern void* _start;

#define SUCCESS 100
#define FAILED_TO_GET_TOTAL_SIZE 1
#define PT_INTERP_PLACEHOLDER 0x69

static int loaded_interpreter = 0;
#define EXECUTABLE_BASE_ADDRESS 0x400000

// this is the ELFs entry
uint64_t load_interpreter_internal()
{
    const Elf64_Ehdr* interp_elf_ex = (const Elf64_Ehdr*)(INTERPRETER);

    const Elf64_Phdr* interp_elf_phdata = (const Elf64_Phdr*)(INTERPRETER + interp_elf_ex->e_phoff);

    unsigned long total_size;
	Elf64_Phdr *eppnt = interp_elf_phdata;
    unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long error = ~0UL;
	int i;



	total_size = total_mapping_size(interp_elf_phdata,
					                interp_elf_ex->e_phnum);

    if (!total_size) {
        return FAILED_TO_GET_TOTAL_SIZE;
    }
    
	for (i = 0; i < interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int elf_type = MAP_PRIVATE;
			int elf_prot = PROT_EXEC | PROT_READ | PROT_WRITE; // TODO: copy kernel's make_prot
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_type |= MAP_FIXED;
			else if (true && interp_elf_ex->e_type == ET_DYN)
				load_addr = -vaddr;

			map_addr = elf_map(INTERPRETER, load_addr + vaddr,
					eppnt, elf_prot, elf_type, total_size);
			total_size = 0;
			error = map_addr;
			// if (BAD_ADDR(map_addr))
			// 	goto out;

			if (!load_addr_set &&
			    interp_elf_ex->e_type == ET_DYN) {
				load_addr = map_addr - ELF_PAGESTART(vaddr);
				load_addr_set = 1;
			}

			// /*
			//  * Check to see if the section's size will overflow the
			//  * allowed task size. Note that p_filesz must always be
			//  * <= p_memsize so it's only necessary to check p_memsz.
			//  */
			// k = load_addr + eppnt->p_vaddr;
			// if (//BAD_ADDR(k) ||
			//     eppnt->p_filesz > eppnt->p_memsz ||
			//     eppnt->p_memsz > TASK_SIZE ||
			//     TASK_SIZE - eppnt->p_memsz < k) {
			// 	error = -ENOMEM;
			// 	goto out;
			// }
		}
	}

    Elf64_Phdr* phdr = ((const Elf64_Ehdr*)(EXECUTABLE_BASE_ADDRESS))->e_phoff + EXECUTABLE_BASE_ADDRESS;
    // patch PT_INTERP
    for (i = 0; ; i++) {
		if (phdr[i].p_type == PT_INTERP_PLACEHOLDER) {
            phdr[i].p_type = PT_INTERP;
            break;
		}
	}
    

    loaded_interpreter = 1;

	error = load_addr;
out:
	return error;
}

uint64_t interpreter_load_addr = 0;

// --------------------------- DLOPEN HOOKS --------------------------------

#define byte uint8_t
#define TRAMPOLINE_SIZE 12

byte original_bytes[10][TRAMPOLINE_SIZE];

void my_memcpy(byte * dst, byte *src, size_t count)
{
    for (int i = 0; i < count; i++) {
        dst[i] = src[i];
    }
}

void hook_function(void * function_to_hook, void * hook_function, size_t hook_index)
{
    // mprotect
    // mprotect(ELF_PAGESTART((uint64_t)function_to_hook), TRAMPOLINE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);

    my_memcpy(original_bytes[hook_index], (byte*)function_to_hook, TRAMPOLINE_SIZE);

    #define MOVABS_RAX 0xb848
    *((uint16_t *)function_to_hook) = MOVABS_RAX;
    *((uint64_t *)(function_to_hook + 2)) = hook_function;
    #define JMP_RAX 0xe0ff
    *((uint16_t *)(function_to_hook + 10)) = JMP_RAX;
}


int my_strcmp(char *a, char*b)
{
    while (*a != '\0' && *b != '\0') {
        if (*a != *b) {
            return 0;
        }

        a++;
        b++;
    }

    if (*a != *b) {
        return 0;
    }

    return 1;
}

#define LIBC_FILE_SIZE 2216304
static unsigned char LIBC[LIBC_FILE_SIZE] = "LIBC_HERE";

byte* FAKE_FD_TO_FILE_BUFFER[64];
int current_fake_fd = 10;

// open hook
#define OPEN64_ADDRESS interpreter_load_addr + 0x026B00
#define OPEN64_HOOK_INDEX 0
typedef int (* __open64_nocancel_pointer) (const char *, int, ...);

int
__open64_nocancel_hook (const char *file, int oflag, ...)
{
    my_memcpy((byte*)OPEN64_ADDRESS, original_bytes[OPEN64_HOOK_INDEX], TRAMPOLINE_SIZE);

    int return_value;
    // printf("open hooked! %s\n", file);
    if (my_strcmp(file, "/lib/x86_64-linux-gnu/libc.so.6")) {
        current_fake_fd++;
        FAKE_FD_TO_FILE_BUFFER[current_fake_fd] = LIBC;
        return_value = current_fake_fd;
    }
    else {
        return_value = ((__open64_nocancel_pointer)OPEN64_ADDRESS)(file, oflag);
    }

    hook_function((void*)OPEN64_ADDRESS, &__open64_nocancel_hook, OPEN64_HOOK_INDEX);


    return return_value;
}


// read hook
#define read_ADDRESS interpreter_load_addr + 0x26B80
#define read_HOOK_INDEX 1
typedef int (* __read_nocancel_pointer) (int, void*, size_t);

ssize_t
__read_nocancel_hook (int fd, void *buf, size_t nbytes)
{
    my_memcpy((byte*)read_ADDRESS, original_bytes[read_HOOK_INDEX], TRAMPOLINE_SIZE);

    ssize_t return_value;
    // printf("open hooked! %s\n", file);
    if (fd != -1 && FAKE_FD_TO_FILE_BUFFER[fd]) {
        byte *buffer = FAKE_FD_TO_FILE_BUFFER[fd];
        my_memcpy(buf, buffer, nbytes);

        // FAKE_FD_TO_FILE_BUFFER[fd] += nbytes;

        return_value = nbytes;
    }
    else {
        return_value = ((__read_nocancel_pointer)read_ADDRESS)(fd, buf, nbytes);
    }

    hook_function((void*)read_ADDRESS, &__read_nocancel_hook, read_HOOK_INDEX);


    return return_value;
}

// pread64 hook
#define pread64_ADDRESS interpreter_load_addr + 0x26BB0
#define pread64_HOOK_INDEX 2
typedef int (* __pread64_nocancel_pointer) (int, void*, size_t, uint64_t);

ssize_t
__pread64_nocancel_hook (int fd, void *buf, size_t count, uint64_t offset)
{
    my_memcpy((byte*)pread64_ADDRESS, original_bytes[pread64_HOOK_INDEX], TRAMPOLINE_SIZE);

    ssize_t return_value;
    // printf("open hooked! %s\n", file);
    if (fd != -1 && FAKE_FD_TO_FILE_BUFFER[fd]) {
        byte *buffer = FAKE_FD_TO_FILE_BUFFER[fd];
        my_memcpy(buf, buffer + offset, count);

        // FAKE_FD_TO_FILE_BUFFER[fd] += nbytes;

        return_value = count;
    }
    else {
        return_value = ((__pread64_nocancel_pointer)pread64_ADDRESS)(fd, buf, count, offset);
    }

    hook_function((void*)pread64_ADDRESS, &__pread64_nocancel_hook, pread64_HOOK_INDEX);


    return return_value;
}

// fstat hook
#define fstat_ADDRESS interpreter_load_addr + 0x268F0
#define fstat_HOOK_INDEX 3
typedef int (* __fstat_pointer) (int , const char *, struct __stat64_t64 *, int);

ssize_t
__fstat_hook (int fd, const char *file, struct __stat64_t64 *buf, int flag)
{
    my_memcpy((byte*)fstat_ADDRESS, original_bytes[fstat_HOOK_INDEX], TRAMPOLINE_SIZE);

    ssize_t return_value;
    // printf("open hooked! %s\n", file);
    if (fd != -1 && FAKE_FD_TO_FILE_BUFFER[fd]) {
        return_value = ((__fstat_pointer)fstat_ADDRESS)(1, file, buf, flag);
    }
    else {
        return_value = ((__fstat_pointer)fstat_ADDRESS)(fd, file, buf, flag);
    }

    hook_function((void*)fstat_ADDRESS, &__fstat_hook, fstat_HOOK_INDEX);


    return return_value;
}

// mmap hook
#define mmap_ADDRESS interpreter_load_addr + 0x26cc0
#define mmap_HOOK_INDEX 4
typedef uint64_t (* __mmap_pointer) (void *, size_t, int, int, int, uint64_t);

uint64_t
__mmap_hook (void *addr, size_t len, int prot, int flags, int fd, uint64_t offset)
{
    my_memcpy((byte*)mmap_ADDRESS, original_bytes[mmap_HOOK_INDEX], TRAMPOLINE_SIZE);

    uint64_t return_value;

    if (fd != -1 && FAKE_FD_TO_FILE_BUFFER[fd]) {
        return_value = ((__mmap_pointer)mmap_ADDRESS)(addr, len, prot | PROT_WRITE, flags | MAP_ANONYMOUS, -1, 0);

        if (return_value > 0) {
            // TODO: get real size instead of LIBC_FILE_SIZE

            for (unsigned long i = 0; i < len; i++) {
                ((unsigned char*)return_value)[i] = 0;
            }

            // basically memcpy
            for (unsigned long i = 0; i < len; i++) {
                if (offset + i >= LIBC_FILE_SIZE) {
                    ((unsigned char*)return_value)[i] = 0;
                    continue;
                }
                ((unsigned char*)return_value)[i] =  FAKE_FD_TO_FILE_BUFFER[fd][offset + i];
            }
            // memcpy(return_value, FAKE_FD_TO_FILE_BUFFER[fd] + offset, min(len + offset, LIBC_FILE_SIZE));
        }
    }
    else {
        return_value = ((__mmap_pointer)mmap_ADDRESS)(addr, len, prot, flags, fd, offset);
    }

    hook_function((void*)mmap_ADDRESS, &__mmap_hook, mmap_HOOK_INDEX);


    return return_value;
}

// close hook
#define close_ADDRESS interpreter_load_addr + 0x269F0
#define close_HOOK_INDEX 5
typedef int (* __close_pointer) (int);

int
__close_hook (int fd)
{
    my_memcpy((byte*)close_ADDRESS, original_bytes[close_HOOK_INDEX], TRAMPOLINE_SIZE);

    int return_value;

    if (fd != -1 && FAKE_FD_TO_FILE_BUFFER[fd]) {
        FAKE_FD_TO_FILE_BUFFER[fd] = NULL;
    }
    else {
        return_value = ((__close_pointer)close_ADDRESS)(fd);
    }

    hook_function((void*)close_ADDRESS, &__close_hook, close_HOOK_INDEX);


    return return_value;
}

void hook_dlopen_functions()
{
    for (int i = 0; i < sizeof(FAKE_FD_TO_FILE_BUFFER) / sizeof(void*); i++) {
        FAKE_FD_TO_FILE_BUFFER[i] = 0;
    }

    hook_function((void*)OPEN64_ADDRESS, &__open64_nocancel_hook, OPEN64_HOOK_INDEX);
    hook_function((void*)read_ADDRESS, &__read_nocancel_hook, read_HOOK_INDEX);
    hook_function((void*)pread64_ADDRESS, &__pread64_nocancel_hook, pread64_HOOK_INDEX);
    hook_function((void*)fstat_ADDRESS, &__fstat_hook, fstat_HOOK_INDEX);
    hook_function((void*)mmap_ADDRESS, &__mmap_hook, mmap_HOOK_INDEX);
    hook_function((void*)close_ADDRESS, &__close_hook, close_HOOK_INDEX);
    
}

// -----------------------

typedef int (*entry_func_signature)(int, char*[], char*[]);

int __attribute__((stdcall)) __attribute__((noreturn)) __attribute__((naked)) load_interpreter() 
{
    if (loaded_interpreter) {
        // directly jump to our real entry function
        __asm__ __volatile__(
        "jmp *%0"
        :
        : "r"( &_start)
    );        
    }

    interpreter_load_addr = load_interpreter_internal();

    hook_dlopen_functions();

    uint64_t * argc;
    __asm__ __volatile__(
        "mov %%rsp, %0"  // Move RSP register into the output operand
        : "=r" (argc)  // Output: assign to rsp_value
    );

    // Overwrite first argv as interpreter path;
    // argc[1] = "ld-linux-x86-64.so.2";

    uint64_t *envp = argc + *argc + 2;

    int i = 0;
    while (envp[i] != NULL) {
        i++;
    }
    // auxv = envp + i + 1
    #define INTERPRETER_LOAD_ADDRESS_AUXV_OFFSET 15 // In qwords
    envp[i + 1 + INTERPRETER_LOAD_ADDRESS_AUXV_OFFSET] = interpreter_load_addr;

    
    // directly jump to our real entry function
    __asm__ __volatile__(
        "jmp *%0"
        :
        : "r"( ((const Elf64_Ehdr*)(INTERPRETER))->e_entry + interpreter_load_addr)
    );        

    // // jump to interpreter entry.
    // ((entry_func_signature)(((const Elf64_Ehdr*)(INTERPRETER))->e_entry + interpreter_load_addr))(argc, argv, envp);

      __builtin_unreachable();
}