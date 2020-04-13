# WannaSmile - Solution

Created by [moka](https://discordapp.com/users/661109271148101652)

## Description
> I accidentally executed this weird file that encrypted my important files!\
please help me understand what it does\
<br>
`ssh wannasmile@challenges1.hexionteam.com -p 4000`<br/>
Password: `hexctf`
<br><br>
*This challenge consists of 2 parts.\
**Attached version has the first flag removed.

## Solution
the given ELF doesn't do anything intersting,\
it prints this braille art of chika:
```
⢸⣿⣿⣿⣿⠃⠄⢀⣴⡾⠃⠄⠄⠄⠄⠄⠈⠺⠟⠛⠛⠛⠛⠻⢿⣿⣿⣿⣿⣶⣤⡀⠄
⢸⣿⣿⣿⡟⢀⣴⣿⡿⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿⣿⣿⣿⣷
⢸⣿⣿⠟⣴⣿⡿⡟⡼⢹⣷⢲⡶⣖⣾⣶⢄⠄⠄⠄⠄⠄⢀⣼⣿⢿⣿⣿⣿⣿⣿⣿⣿
⢸⣿⢫⣾⣿⡟⣾⡸⢠⡿⢳⡿⠍⣼⣿⢏⣿⣷⢄⡀⠄⢠⣾⢻⣿⣸⣿⣿⣿⣿⣿⣿⣿
⡿⣡⣿⣿⡟⡼⡁⠁⣰⠂⡾⠉⢨⣿⠃⣿⡿⠍⣾⣟⢤⣿⢇⣿⢇⣿⣿⢿⣿⣿⣿⣿⣿
⣱⣿⣿⡟⡐⣰⣧⡷⣿⣴⣧⣤⣼⣯⢸⡿⠁⣰⠟⢀⣼⠏⣲⠏⢸⣿⡟⣿⣿⣿⣿⣿⣿
⣿⣿⡟⠁⠄⠟⣁⠄⢡⣿⣿⣿⣿⣿⣿⣦⣼⢟⢀⡼⠃⡹⠃⡀⢸⡿⢸⣿⣿⣿⣿⣿⡟
⣿⣿⠃⠄⢀⣾⠋⠓⢰⣿⣿⣿⣿⣿⣿⠿⣿⣿⣾⣅⢔⣕⡇⡇⡼⢁⣿⣿⣿⣿⣿⣿⢣
⣿⡟⠄⠄⣾⣇⠷⣢⣿⣿⣿⣿⣿⣿⣿⣭⣀⡈⠙⢿⣿⣿⡇⡧⢁⣾⣿⣿⣿⣿⣿⢏⣾
⣿⡇⠄⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢻⠇⠄⠄⢿⣿⡇⢡⣾⣿⣿⣿⣿⣿⣏⣼⣿
⣿⣷⢰⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⢰⣧⣀⡄⢀⠘⡿⣰⣿⣿⣿⣿⣿⣿⠟⣼⣿⣿
⢹⣿⢸⣿⣿⠟⠻⢿⣿⣿⣿⣿⣿⣿⣿⣶⣭⣉⣤⣿⢈⣼⣿⣿⣿⣿⣿⣿⠏⣾⣹⣿⣿
⢸⠇⡜⣿⡟⠄⠄⠄⠈⠙⣿⣿⣿⣿⣿⣿⣿⣿⠟⣱⣻⣿⣿⣿⣿⣿⠟⠁⢳⠃⣿⣿⣿
⠄⣰⡗⠹⣿⣄⠄⠄⠄⢀⣿⣿⣿⣿⣿⣿⠟⣅⣥⣿⣿⣿⣿⠿⠋⠄⠄⣾⡌⢠⣿⡿⠃
⠜⠋⢠⣷⢻⣿⣿⣶⣾⣿⣿⣿⣿⠿⣛⣥⣾⣿⠿⠟⠛⠉⠄⠄
```

and does some random calculations.\
but something else within the ELF is interesting,\
`readelf -a ./hmmm`\
shows that there are unusual section names,
one of which is `.note.f14g`.

the next step would be displaying the notes
```
$ readelf -n ./hmmm

Displaying notes found in: .note.f14g
readelf: Warning: Corrupt note: alignment 32, expecting 4 or 8
```

but the section is corrupt, maybe we can try to hexdump it
```
$ objdump -j .note.f14g -s hmmm

Contents of section .note.f14g:
 0380 68000000 00000000 00000000 00000000  h...............
 0390 00000000 00000000 00000000 00000000  ................
 03a0 00000000 00000000 00000000 65000000  ............e...
 03b0 00000000 00000000 00000000 00000000  ................
 03c0 00000000 00000000 00000000 00000000  ................
 03d0 00000000 00000000 00000000 00000000  ................
 03e0 00000000 00000000 00000000 00000000  ................
 03f0 00000000 00000000 00000000 78000000  ............x...
 ...
 ...
```
and there's the flag.


to extract the flag we can use this short snippet:
```python
from pwn import ELF

section = ELF('./hmmm').get_section_by_name('.note.f14g').data()
print(''.join([chr(_) for _ in section if _ != 0]))
```
or... you could `cat ./hmm`

Flag: `hexCTF{1m_s0rry_1f_y0u_r3v3r5ed_7h1s}`\
(I'm actually sorry for your suffering)