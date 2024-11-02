#include "libhook.h"

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
