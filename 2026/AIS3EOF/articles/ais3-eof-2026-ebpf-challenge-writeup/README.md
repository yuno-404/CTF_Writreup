---
title: AIS3 EOF 2026 - eBPF Challenge Writeup
tags: [CTF]

---

這是一份針對這道 eBPF Reverse Engineering 挑戰的完整 Writeup。

---

# AIS3 EOF 2026 - eBPF Challenge Writeup

## 1. 題目概觀 (Challenge Overview)

題目提供了三個檔案：

1. 
**`flag.enc`**: 一個包含 Hex 字串的檔案，內容為 `eabbc25677f3084458f0531f86863f226c95d555e6c28bd7`。


2. 
**`loader`**: 一個 User Space 的載入程式，負責將 eBPF 程式掛載到核心，並從 Perf Buffer 讀取資料。從其字串可以看到 `[+] Encoded Flag (Hex):`，暗示 `flag.enc` 是 eBPF 程式處理後的輸出。


3. 
**`xdp_prog.o`**: 核心的 eBPF Object file，包含一個名為 `xdp_encoder` 的 XDP 程式區段。



**目標：** 逆向分析 `xdp_prog.o` 中的加密邏輯，將 `flag.enc` 解密回原始 Flag。

---

## 2. 逆向分析 (Reverse Engineering)

### 2.1 初步分析

透過 `loader` 的行為與 `xdp_prog.o` 的名稱，可以推斷這是一個 XDP (eXpress Data Path) 程式。它會在核心層級攔截網路封包，修改或讀取封包內容（Flag），進行運算後傳回 User Space。

### 2.2 靜態分析 (Static Analysis)

使用 `llvm-objdump -d xdp_prog.o` 或 `objdump` 查看 `xdp` 區段的組合語言。

我們關注 `<xdp_encoder>` 函式中的核心邏輯。程式首先檢查封包標頭（Ethernet, IP），然後檢查 UDP Destination Port 是否為 `10275` (0x2823)（見指令行 20 `if r4 != 10275`）。

接著，程式進入一段展開的迴圈 (Unrolled Loop)，針對封包 Payload (Offset 42 開始) 的每一個 Byte 進行 XOR 運算。

**關鍵指令範例：**
從 `xdp_prog.o` 的反組譯結果中，我們可以看到重複的模式：讀取 Byte -> XOR 常數 -> 存入 Stack。

* **Byte 0 (Offset 42):**
```assembly
34: r4 = *(u8 *)(r2 + 42)  // 讀取第 0 個 byte
35: r4 ^= 175              // XOR Key = 175 (0xAF)

```


* **Byte 1 (Offset 43):**
```assembly
41: r4 = *(u8 *)(r2 + 43)  // 讀取第 1 個 byte
42: r4 ^= 244              // XOR Key = 244 (0xF4)

```


* **Byte 2 (Offset 44):**
```assembly
48: r4 = *(u8 *)(r2 + 44)  // 讀取第 2 個 byte
49: r4 ^= 132              // XOR Key = 132 (0x84)

```



這個模式一直持續下去。由於 XOR 是對稱運算 (`(A ^ K) ^ K = A`)，我們只需要提取這些 Hardcoded 的常數（Key），再與 `flag.enc` 進行 XOR 即可還原。

---

## 3. 解密腳本 (Solver Script)

根據反組譯碼提取前 24 個 Bytes 的 Key，並撰寫 Python 腳本如下：

```python
#!/usr/bin/env python3

# [cite_start]1. Encoded data from flag.enc [cite: 1]
encoded_hex = "eabbc25677f3084458f0531f86863f226c95d555e6c28bd7"
encoded_bytes = bytes.fromhex(encoded_hex)

# 2. XOR Keys extracted from xdp_prog.o disassembly
# Logic found in instructions: r4 ^= CONSTANT
keys = [
    175, # Offset 42
    244, # Offset 43
    132, # Offset 44
    45,  # Offset 45
    4,   # Offset 46
    154, # Offset 47
    57,  # Offset 48
    15,  # Offset 49
    43,  # Offset 50
    192, # Offset 51
    29,  # Offset 52
    120, # Offset 53
    217, # Offset 54
    183, # Offset 55
    10,  # Offset 56
    125, # Offset 57
    11,  # Offset 58
    165, # Offset 59
    186, # Offset 60
    17,  # Offset 61
    185, # Offset 62
    150, # Offset 63
    187, # Offset 64
    170  # Offset 65
]

# 3. Decryption Routine
flag = ""
print(f"[*] Decrypting {len(encoded_bytes)} bytes...")

for i in range(len(encoded_bytes)):
    if i < len(keys):
        # XOR operation to reverse the encryption
        decrypted_char = chr(encoded_bytes[i] ^ keys[i])
        flag += decrypted_char
        # Optional: Print debug info
        # print(f"Byte {i}: {hex(encoded_bytes[i])} ^ {keys[i]} = {decrypted_char}")

print(f"\n[+] Flag: {flag}")

```

---

## 4. 結果 (Result)

執行上述腳本後的運算過程：

* `0xea` ^ `175` = **E**
* `0xbb` ^ `244` = **O**
* `0xc2` ^ `132` = **F**
* `0x56` ^ `45`  = **{**

最終 Flag 為：

Flag: EOF{si1Ks0Ng_15_g0oD_T0}



