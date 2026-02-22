---
title: idekCTF2025 constructor
tags: [CTF, rev]

---

這次一樣只寫了一題，關於逆向的題目
一個被 strip 的 64 位元 ELF 檔案

strip過後的檔案會讓我們無法直接透過名稱去找到想要看的function，現在連找main都汗流浹背

![image](https://hackmd.io/_uploads/S1knUI3vlg.png)



先做starti

![image](https://hackmd.io/_uploads/HyIdvI2Pge.png)

## 為什麼一開始使用 starti？
starti 是 GDB（GNU Debugger）中的一個指令，全名是 start instruction。
意思是：「讓程式在 第一條有效指令 處暫停執行」，而不是從 main() 開始。

目的是什麼？
1. 從最一開始執行（也就是 entry point）
許多逆向題目會埋東西在 main() 之前的階段（像是檢查參數、環境變數、anti-debug 等）
starti 會讓你從 _start 開始一步步觀察執行流程
2. 避免 miss 掉 early logic（早期邏輯）
如果你直接從 main 下 breakpoint，會跳過 libc 初始化等重要過程
3. 進一步讓你 trace 到 main 的實際位址

再來是尋找main，用x/20i顯示
![image](https://hackmd.io/_uploads/HJdhKU2Pel.png)

第一個紅框框等等再說
第二個紅框框是在call main

這裡把某個常數 0x401170 放進 rdi 暫存器，而在呼叫 __libc_start_main 的時候：

rdi 是第一個參數（按照 x86-64 的 calling convention）

第一個參數 → 就是 main 函數的指標！

```
int __libc_start_main(
    int (*main) (int, char **, char **),
    int argc,
    char **ubp_av,
    void (*init) (void),
    void (*fini) (void),
    void (*rtld_fini) (void),
    void *stack_end
);
```

> 0x401170 就是 main 函數的位址


----

接下來要幹嘛?
先用vmmap看記憶體布局
![image](https://hackmd.io/_uploads/rkfr2N0vxl.png)

再來是推斷.rodata位置
* r--p: 唯讀 (Read-only)。程式碼可以讀取這裡的資料，但不能寫入或執行。
* r-xp: 可讀可執行 (Read-execute)。這是儲存程式碼 (.text) 的地方。
* rw-p: 可讀可寫 (Read-write)。這是儲存可變資料 (.data, .bss) 的地方。

猜測0x403000 - 0x404000 這個區段，因為它是緊跟在程式碼區段後面的第一個唯讀區段，所以它就是 .rodata

> ## 小知識時間
> * .text (Code): 程式碼本身。它是可執行的。
> * .rodata (Read-only Data): 唯讀資料，例如字串常數 ("Hello, world!")、const 變數。把它們放在一個唯讀區段可以防止程式意外地修改它們，增加程式的穩定性和安全性。
> * .data (Initialized Data): 已經被初始化的全域變數和靜態變數（例如 int global_var = 10;）。它是可寫的。
> * .bss (Uninitialized Data): 未被初始化的全域變數和靜態變數。它也是可寫的。

再來是用x/20s查看 字串
![image](https://hackmd.io/_uploads/Bkl86NAwgl.png)

會看到👀，這是在執行檔案時會出現的結果
![image](https://hackmd.io/_uploads/BJQyCN0Pxl.png)

那wrong跟correct又是甚麼?該如何觸發?
還有一個很可疑的/proc/self/cmdline?


到目前為止，我們只知道執行後會有一個👀顯示出來。
但在rodata中，會看到有Wrong跟Correct，代表有可能我們要進去邏輯判斷，才能得到正確的結果

> 甚麼是/proc/self/cmdline?
> /proc/self/cmdline 是 Linux 提供的一個標準介面，讓任何一個正在運行的程式，都可以回過頭來查看自己當初是被什麼樣的指令和參數所啟動的

----
當帶一個參數的時候，顯示了wrong
![image](https://hackmd.io/_uploads/r1GRwvAvll.png)


開始利用動態分析去trace整個過程
![image](https://hackmd.io/_uploads/S1RHdPAwgx.png)
發現0x401770中斷點在帶有參數的時候，並不會停下，也就是被繞過去了，


![image](https://hackmd.io/_uploads/BJbDdv0Pxe.png)

找其他中斷點
![image](https://hackmd.io/_uploads/r1DdovCDlg.png)

我們選0x401770當中斷點
為甚麼不選0x4011b0?
還記得第一個紅框框嗎?

0x4011b0 這段程式碼的功能，不是執行某個應用程式的特定任務，而是作為 _開始 函式的一部分，其最終目的就是準備好所有參數，然後通過 JMP的 指令將程式的控制權徹底移交給 __libc_start_main (0x401570)。
```
0x4011b0:    endbr64
0x4011b4:    mov    esi,DWORD PTR [rdi]  ;  argc
0x4011b6:    lea    rdx,[rdi+0x8]        ;  argv
0x4011ba:    mov    r8,0x4026d4          ;  init
; ...
0x4011cb:    mov    rdi,0x401170         ;  main
0x4011d2:    jmp    0x401570             ; jmp __libc_start_main
```


執行帶有參數的指令後，我們看到flag了
![image](https://hackmd.io/_uploads/BkMt5P0Dee.png)



最後這題，即使沒有帶參數，也可以直接找到flag。
![image](https://hackmd.io/_uploads/SksU6P0wex.png)

----
補充
我們仔細的去看內容
從b *0x4011d2 開始去si ,ni
最後會看到停在0x40154f
![image](https://hackmd.io/_uploads/ByPq0DRDxx.png)

下一個中斷點b *0x40154f
![image](https://hackmd.io/_uploads/ry_byOCPxl.png)

進去到一個迴圈中


當前我已經到第四圈了
* RAX = 3：這是迴圈計數器，代表我們正在處理第 4 個字元 (索引從 0 開始)。
* RDI：指向加密資料的起始位址。
* RBX：指向解密後要寫入的目標緩衝區 (0x405140)。
* ECX = 0x5d：這是上一次迴圈結束後更新的密鑰值。
* EDX：準備用來存放計算的中間值。

這是完美程式如何將加密資料中的第 4 個位元組 0x6d，經過三層 XOR 運算（^ 0x5d，^ 1，^ 0x5a）以及一個變動的密鑰，最終解密成 Flag 中的第 4 個字元 'k' (0x6b) 並存入記憶體的完整過程。