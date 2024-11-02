import pwn

INTERPRETER_PATH = "ld-linux-x86-64.so.2"

with open("main.o", "rb") as file:
    elf_content = file.read()

print(len(elf_content))

interpreter_buffer_offset = elf_content.find(b"INTERPRETER_HERE")
print(interpreter_buffer_offset)

with open(INTERPRETER_PATH, "rb") as interpreter:
    interpreter_content = interpreter.read()
    print(len(interpreter_content))
    elf_content = elf_content[:interpreter_buffer_offset] + interpreter_content + elf_content[interpreter_buffer_offset + len(interpreter_content):]


LIBC_PATH = "libc.so.6"

interpreter_buffer_offset = elf_content.find(b"LIBC_HERE")
print(interpreter_buffer_offset)

with open(LIBC_PATH, "rb") as interpreter:
    interpreter_content = interpreter.read()
    print(len(interpreter_content))
    elf_content = elf_content[:interpreter_buffer_offset] + interpreter_content + elf_content[interpreter_buffer_offset + len(interpreter_content):]


# remove pt_interp
pt_interp_offset = 0x78

PT_INTERP_PLACEHOLDER = b'\x69'

elf_content = elf_content[:pt_interp_offset] + PT_INTERP_PLACEHOLDER + elf_content[pt_interp_offset + 1:]

# make first pt_load segment writable
first_pt_load_flags_offset = 0xB4
READ_WRITE = b'\x06'
elf_content = elf_content[:first_pt_load_flags_offset] + READ_WRITE + elf_content[first_pt_load_flags_offset + 1:]

with open("main.o", "wb") as file:
    file.write(elf_content)


