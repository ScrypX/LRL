#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <errno.h>
extern void* _start;

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

int main()
{
    printf("%d\n", my_strcmp("abcde", "abcde"));
    printf("%d\n", my_strcmp("abcde", "cbcde"));
    printf("%d\n", my_strcmp("abcde", "abcdef"));
    printf("%d\n", my_strcmp("abcdef", "abcdefe"));

    // unsigned long result = mmap_custom(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1 , 0);
    // printf("Result: %p, errno: %d\n", result, errno);

    // result = mmap_custom(result + 100, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1 , 0);

    // printf("Result: %p, errno: %d\n", result, errno);
    // printf("Hello world %p\n", &_start);
    // printf("%d\n", sizeof(unsigned long));

    // Inline assembly to jump to the address of jump_to_label
    // __asm__ __volatile__(
    //     "jmp *%0"
    //     :
    //     : "r"( &_start)
    // );

    return 0;
}