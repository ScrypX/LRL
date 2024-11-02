#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <errno.h>
#include <dlfcn.h>

byte original_bytes[10][TRAMPOLINE_SIZE];

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

// void x()
// {
//     printf("this is x\n");
// }

// void x_hook()
// {
//     my_memcpy((byte*)&x, original_bytes[0], TRAMPOLINE_SIZE);

//     printf("this is x hooked\n");
//     x();
    
//     hook_function((void*)&x, &x_hook, 0);
// }

uint64_t ld_base = 0;

#define OPEN64_ADDRESS ld_base + 0x026B00
#define OPEN64_HOOK_INDEX 0
typedef int (* __open64_nocancel_pointer) (const char *, int, ...);

int
__open64_nocancel_hook (const char *file, int oflag, ...)
{
    my_memcpy((byte*)OPEN64_ADDRESS, original_bytes[OPEN64_HOOK_INDEX], TRAMPOLINE_SIZE);

    printf("open hooked! %s\n", file);
    ((__open64_nocancel_pointer)OPEN64_ADDRESS)(file, oflag);

    hook_function((void*)OPEN64_ADDRESS, &__open64_nocancel_hook, OPEN64_HOOK_INDEX);
}


int main()
{
    printf("Hello world!\n");
    scanf("%p", &ld_base);

    hook_function((void*)OPEN64_ADDRESS, &__open64_nocancel_hook, OPEN64_HOOK_INDEX);

    dlopen("blabla.so", RTLD_LAZY);

    return 0;
}

