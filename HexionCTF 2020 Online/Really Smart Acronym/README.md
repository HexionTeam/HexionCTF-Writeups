# Really Smart Acronym - Solution

Created by Yarin ([GitHub](https://github.com/CmdEngineer) / [Twitter](https://twitter.com/CmdEngineer_))

## Description

Man, oracles are weird.

`nc challenges1.hexionteam.com 5000`

## Attached Script

```py
from Crypto.Util.number import bytes_to_long
from Crypto.PublicKey import RSA
from secret import flag
import os

key = RSA.generate(1024)
print("Flag:", pow(bytes_to_long(flag), key.e, key.n))

print("One encrypt:")
m = int(input("m => "))
print(pow(m, key.e, key.n))

print("Alot of unhelpful decrypts:")
for i in range(int(os.getenv("MAX_TRIES") or 1024)):
    c = int(input("> "))
    print(bin(pow(c, key.d, key.n))[-1])
```

## Solution

The attached script is the server file that is listening on the nc. We can see a few things on the serrver:

1. We have the flag encrypted
2. We have one encrypt
3. We know the LSB (Least Significant Bit) of alot of decrypts

After testing `RSA.generate(1024)` alot of times we can see `e` is usally `0x10001`. \
We need to find `n`, to do so we can use the one encrypt.

A cool trick in python is:

```py
>>> pow(-1, 0x10001, 100000)
99999
```

That is:
`-1 % n = n - 1`

`(-1) ** e` where `e` is a negative number = `-1`

This will allow us to receive `n - 1` by sending the server `-1`

Now we have alot of LSB decrypts we can use an LSB Oracle which basically work like a binary search, each time you multiply `c` (the encrypted flag) by `2 ** i % n` (i is the current bit index). Because of modular arthimtic this will be the same as `c * 2 ** i`.  
We send this to the server it will tell us if the decrypted result is even or odd (the last bit of a binary number). If it's even then `c * 2 ** i` overlapped `n` meaning `c` is smaller than the current maximum so we can halve it. If it'd odd the same but for the lower minimum.

### Script

```py
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from pwn import *

p = remote("challenges1.hexionteam.com", 5000)
p.recvuntil("Flag: ")
c = int(p.recvuntil("\nO", drop=True))
e = 0x10001

p.recvuntil("=> ", drop=True)
p.sendline("-1")

n = int(p.recvuntil("Alot of unhelpful decrypts:", drop=True)) + 1
p.recvuntil("> ")
_max = n
_min = 0
i = 1
try:
    while i <= 1024:
        p.sendline(str(c * pow(2 ** i, e, n)))
        a = p.recvuntil("\n> ", drop=True)
        if b"0" == a:
            # even
            _max = (_max + _min) // 2
        else:
            # odd
            _min = (_max + _min) // 2
        i += 1
except:
    pass
print(long_to_bytes(_max))
```

Flag: `hexCTF{n1c3_r5a_tr1ck5_m4t3}`
