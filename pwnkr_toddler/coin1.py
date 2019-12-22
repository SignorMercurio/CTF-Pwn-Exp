from pwn import *
import re

p = remote('localhost', 9007)
ret = p.recv()
sleep(3)

for i in range(100):
	ret = p.recv()
	N = ret[ret.find("N=")+2:ret.find(" ")]
	C = ret[ret.find("C=")+2:ret.find("\n")]
	low = 0
	high = int(N)
	for j in range(int(C)):
		cnt = (high-low) / 2
		mid = low + cnt
		query = ' '.join([str(i) for i in range(low, mid)])
		p.sendline(query)
		ret = p.recv()
		if int(ret) % 10 == 0:
			low = mid
		else:
			high = mid
	p.sendline(str(low))
	print p.recv()

print p.recv()