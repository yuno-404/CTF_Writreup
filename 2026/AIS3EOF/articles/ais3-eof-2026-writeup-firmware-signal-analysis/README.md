---
title: 'AIS3 EOF 2026 Writeup: Firmware & Signal Analysis'
tags: [CTF]

---

這是一份針對此 CTF 題目完整的 Writeup (解題報告)。
board
---

# CTF Writeup: Firmware & Signal Analysis

**題目類型**: Reverse Engineering / Hardware / IoT
**檔案**: `firmware.bin` (ARM Cortex-M 韌體), `signal.vcd` (邏輯分析儀波形檔)

## 解題思路總結

這道題目模擬了一個 IoT 設備的逆向場景。我們透過分析 `signal.vcd` 截獲了傳輸到設備的輸入字串（Key），然後逆向 `firmware.bin` 找出加密演算法（RC4）與密文，最後結合兩者解密出 Flag。

---

### 步驟 1：訊號分析 (Signal Analysis)

首先處理 `signal.vcd`。这是一个記錄數位訊號變化的檔案。

1. **識別協定**：
* 打開檔案（可使用 PulseView 或 GTKWave），觀察到只有一條名為 `d` 的數據線。
* 訊號呈現規律的高低電位變化，且閒置時為高電位 (High)，起始位元 (Start Bit) 拉低。這是典型的 **UART (Universal Asynchronous Receiver-Transmitter)** 序列通訊。


2. **計算鮑率 (Baud Rate)**：
* 測量最小脈衝寬度 (1 bit duration)。
* 觀察 VCD 時間戳記，發現最小寬度約為 。
* 計算鮑率：。


3. **解碼數據**：
* 使用 9600 鮑率對訊號進行解碼（8N1 格式）。
* **關鍵發現**：初次解碼可能誤判為 `b4r3_m3t4l`，但仔細比對波形精確度後，正確的字串應包含大小寫與數字替換：
* **Decoded Key**: **`b4r3MEt41`**
* 注意：是大寫 `M`、大寫 `E`，且最後是數字 `1`。





---

### 步驟 2：韌體逆向 (Firmware Reverse Engineering)

接著分析 `firmware.bin` 以了解設備如何處理這個輸入。

1. **識別架構與載入 (IDA Pro)**：
* 檔案沒有標準標頭 (Header)，是 Bare-metal binary。
* 透過觀察前 4 bytes `0x2000xxxx` (Stack Pointer) 和 `0x0000xxxx` (Reset Vector)，確認為 **ARM Cortex-M (Little Endian)**。
* **IDA 設定**：Processor: `ARM Little-endian`, Architecture: `ARMv7-M`, Base Address: `0x00000000`。
* **模式設定**：Reset Vector (0x04 處) 指向 `0x351`，因為最後 1 bit 為 1，代表 **Thumb Mode**。在 IDA 中將 `0x350` 處設為 Code (`T=1`)。


2. **程式邏輯分析**：
* **Entry Point**: `Reset_Handler` (`0x350`) 初始化記憶體後跳轉到 `main` (`sub_2A0`)。
* **Main Function (`sub_2A0`)**:
* 印出 "Input: "。
* 讀取 UART 輸入。
* 呼叫 **`sub_44`** 進行處理。
* 從 `0x394` 讀取一串數據 (`unk_394`)，與運算結果進行 XOR 並輸出。




3. **識別演算法 (RC4)**：
* 進入 **`sub_44`** 分析：
* 看到兩個 `0` 到 `255` 的迴圈。
* 第一個迴圈初始化陣列 `S[i] = i`。
* 第二個迴圈根據 Key 打亂陣列：`j = (j + S[i] + Key[i]) % 256`，然後交換 `S[i]` 與 `S[j]`。


* 這是教科書等級的 **RC4 Key Scheduling Algorithm (KSA)** 特徵。
* 隨後的 XOR 操作對應 RC4 的 **PRGA** 生成密鑰流。


4. **提取關鍵數據**：
* **Ciphertext (密文)**: 位於 binary 的 `0x394` 位址。
* Bytes: `A2 C3 9E CC 60 35 EE BF ...`





---

### 步驟 3：解密 (Decryption)

結合我們在 VCD 拿到的 Key (`b4r3MEt41`) 和在 Firmware 拿到的密文與演算法 (RC4)，撰寫腳本求解。

**Python 解題腳本 (`solve.py`)**:

```python
def rc4_decrypt(ciphertext, key_str):
    # Convert Key to bytes
    key = [ord(c) for c in key_str]
    
    # 1. KSA (Key Scheduling Algorithm)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i] # Swap

    # 2. PRGA (Pseudo-Random Generation Algorithm) & Decrypt
    i = 0
    j = 0
    res = []
    for byte in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i] # Swap
        K = S[(S[i] + S[j]) % 256]
        res.append(byte ^ K) # XOR decrypt
    
    return bytes(res)

# 從 firmware.bin 0x394 提取的密文
ciphertext = [
    0xA2, 0xC3, 0x9E, 0xCC, 0x60, 0x35, 0xEE, 0xBF, 0xF5, 0x7D, 
    0x78, 0x5A, 0xCD, 0xD5, 0xC8, 0x52, 0x80, 0xAE, 0xC6, 0x19, 
    0x56, 0xF2, 0xA7, 0xCB, 0xD5, 0x0B, 0xE1, 0x61, 0xB9, 0x14
]

# 從 signal.vcd 精確分析出的 Key
# 注意：大小寫敏感，且最後是數字 1
key = "b4r3MEt41"

print(f"[*] Trying Key: {key}")
decrypted = rc4_decrypt(ciphertext, key)

try:
    print(f"[*] Decrypted: {decrypted}")
    print(f"[+] Flag: {decrypted.decode('utf-8')}")
except:
    print("[!] Decoding error")

```

### 結果 (Conclusion)

執行腳本後，解密出的明文即為 Flag。

EOF{ExP3d14i0N_33_15_4he_G0AT}


