---
title: 'AIS3 EOF 2026  Writeup: Structured small'
tags: [CTF]

---

這是一份針對您提供的 Reverse Engineering 題目的完整 Writeup。這類題目通常被稱為 **"Constraint Checking"** 或 **"Linear Equation"** 類型的逆向題。

---

# CTF Writeup: Structured small

## 1. 題目分析 (Challenge Overview)

題目提供了一系列的 C 語言偽代碼（由 IDA Hex-Rays 反編譯產生）。所有的 `main` 函式結構都非常相似，其核心邏輯是將輸入的字串切分成數個區塊（Chunks），將每個區塊轉換為 64-bit 整數，最後檢查該整數是否符合特定的 Hex 數值。

### 核心演算法 (The Packing Loop)

這是所有函式共用的核心邏輯：

```c
v5 = 0LL;
do {
  v7 = (unsigned __int8)*v4; // 讀取一個字元 (char)
  // ...
  v5 = v7 | (v5 << 8);       // 左移 8 bits 後，將新字元放入低位 (LSB)
} while ( ... );

```

**邏輯解讀：**
這個迴圈會將字串「從左到右」依序填入 64-bit 暫存器。
例如字串 `"ABC"` (ASCII `0x41`, `0x42`, `0x43`)：

1. `v5` = `0x41`
2. `v5` = `0x4142`
3. `v5` = `0x414243`

這意味著我們可以直接將 Hex 數值視為 ASCII 字串閱讀，**除了** 某些函式在比對前做了位元運算（ROR, Byteswap）。

---

## 2. 解題過程 (Solution Walkthrough)

我們將題目提供的 10 個片段依序還原。

### Part 1: 普通比對 (Plain Comparison)

這些片段直接比對 `v5` 是否等於某個常數。直接將 Hex 轉 ASCII 即可。

* **Snippet 0:** `0x20666F7220746869`  `" for thi"`
* **Snippet 1:** `0x73206368616C6C65`  `"s challe"`
* **Snippet 2:** `0x6E67652069733A20`  `"nge is: "`
* **Snippet 4:** `0x4354755233445F72`  `"CTuR3D_r"`
* **Snippet 5:** `0x3356335235335F33`  `"3V3R53_3"`
* **Snippet 6:** `0x6E67314E33655231`  `"ng1N3eR1"`
* **Snippet 8:** `0x6339313935303439`  `"c9195049"`

### Part 2: 位元旋轉 (Rotate Right)

這些片段在比對前使用了 `__ROR8__(v5, N)` (Rotate Right)。為了還原原始輸入，我們需要執行逆運算：**Rotate Left (ROL)**。

* **Snippet 3:** `__ROR8__(v5, 24) == 0x545275454F467B35`
* 目標 Hex: `54 52 75 45 4F 46 7B 35`
* 逆運算 (ROL 24 bits / 3 bytes): 將開頭的 3 個 bytes 移到最後面。
* 還原 Hex: `45 4F 46 7B 35 54 52 75`
* ASCII: **`"EOF{5TRu"`**


* **Snippet 7:** `__ROR8__(v5, 16) == 0x66614E675F393036`
* 目標 Hex: `66 61 4E 67 5F 39 30 36`
* 逆運算 (ROL 16 bits / 2 bytes): 將開頭的 2 個 bytes 移到最後面。
* 還原 Hex: `4E 67 5F 39 30 36 66 61`
* ASCII: **`"Ng_906fa"`**



### Part 3: 位元組交換 (Byteswap)

* **Snippet 9:** `_byteswap_uint64(v5) >> 8 == 0xA7D3839663534`
* 程式邏輯：將輸入值 `v5` 進行 Endian 交換，然後右移掉 1 byte (Null byte)，檢查是否等於目標。
* 目標 Hex: `0x000A7D3839663534` (補滿 64-bit)
* 逆運算：直接將目標 Hex 的 Byte 順序反過來讀。
* 順序：`34 35 66 39 38 7D 0A`
* ASCII: **`"45f98}\n"`**



---

## 3. 完整解密腳本 (Solver Script)

為了驗證並自動化這個過程，我們可以使用 Python `struct` 模組：

```python
import struct

def to_str(val):
    return struct.pack('>Q', val).decode('latin-1')

def rol64(val, r):
    return ((val << r) & 0xFFFFFFFFFFFFFFFF) | (val >> (64 - r))

# 1. 收集所有片段的檢查值
chunks = [
    (0, 0x20666F7220746869),          # " for thi"
    (0, 0x73206368616C6C65),          # "s challe"
    (0, 0x6E67652069733A20),          # "nge is: "
    (24, 0x545275454F467B35),         # ROR 24 -> "EOF{5TRu"
    (0, 0x4354755233445F72),          # "CTuR3D_r"
    (0, 0x3356335235335F33),          # "3V3R53_3"
    (0, 0x6E67314E33655231),          # "ng1N3eR1"
    (16, 0x66614E675F393036),         # ROR 16 -> "Ng_906fa"
    (0, 0x6339313935303439),          # "c9195049"
    # 最後一段是 byteswap，手動處理: 45f98}\n
]

flag = ""

for rotate, val in chunks:
    if rotate > 0:
        val = rol64(val, rotate) # 逆運算 ROR -> ROL
    flag += to_str(val)

# 加上最後一段 (手動解碼結果)
flag += "45f98}\n"

print(f"Recovered String: {flag}")

```

---

## 4. 最終結果 (Conclusion)

將所有片段組合後，我們得到完整的句子與 Flag：

**完整訊息：**
` for this challenge is: EOF{5TRuCTuR3D_r3V3R53_3ng1N3eR1Ng_906fac919504945f98}`

**Flag:**

```text
EOF{5TRuCTuR3D_r3V3R53_3ng1N3eR1Ng_906fac919504945f98}

```

這串 Flag 其實是對技術名詞 **"Structured Reverse Engineering"** 進行了 Leet Speak 變形（`5TRuCTuR3D_r3V3R53_3ng1N3eR1Ng`），這也正好呼應了我們利用結構化分析（將程式碼拆解為多個小片段）來解題的過程。