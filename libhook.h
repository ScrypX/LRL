#pragma once

#include <unistd.h>
#include <stdint.h>

#define byte uint8_t
#define TRAMPOLINE_SIZE 12
byte original_bytes[10][TRAMPOLINE_SIZE];

void hook_function(void * function_to_hook, void * hook_function, size_t hook_index);