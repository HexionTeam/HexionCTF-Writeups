# Debug - Solution

Created by Yarin ([GitHub](https://github.com/CmdEngineer) / [Twitter](https://twitter.com/CmdEngineer_))

## Description

Math is so beautiful and can **always** be used for cryptographic encryption!

`nc challenges1.hexionteam.com 5001`

## Attached Script

```py
from Crypto.Util.number import bytes_to_long, getPrime
from random import randint
from secret import flag

MIN = randint(0x30, 0x40)
P = 2**521 - 1

def eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x"""
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def main():
    poly = [bytes_to_long(flag.encode())]
    poly.extend(set([randint(1, P - 1) for i in range(MIN)]))
    print("┌───────────────┐")
    print("│ SSS Encryptor │")
    print("└───────────────┘")
    print("Enter text to encrypt, leave empty to quit.")
    while True:
        data = input(">>> ")
        if bytes_to_long(data.encode()) % P == 0:
            break
        print(eval_at(poly, bytes_to_long(data.encode()), P))  

if __name__ == "__main__":
    main()
```

## Solution

This challenge is based on Shamir Secret Sharing, which is based on polynomials and lagrange interpolation.

Shamir Secret Sharing in short:
Let's say your a dictator, you put your money in a safe that can be opened with some integer code.
You have key supporters, 5 adminstrators that you only trust to open the safe when they come together. (So one can't just steal the money)
You create a polynomial from 4th power that goes through (0, safe_code) and you give each of the people you trust a point from the polynomial.
Only when 5 of them come together can they use all those points to form the only one and true polynomial that can form within them.

The challenge basically hands out how much shares you want, but when creating the polynomial it only goes to MIN which is capped at 0x40 (64)
This mean we can take 64 shares (points) from the server and use lagrange interpolation to calcaulate y for x = 0 and get the flag!

Note: All these functions are taken from the [Wikipedia page of Shamir Secret Sharing.]("https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing")


### Script

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from pwn import *

def _extended_gcd(a, b):
    """
    Division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1) this can
    be computed via extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    """
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    """Compute num / den modulo prime p

    To explain what this means, the return value will be such that
    the following is true: den * _divmod(num, den, p) % p == num
    """
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    """
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order.
    """
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"
    def PI(vals):  # upper-case PI -- product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def recover_secret(shares):
    """
    Recover the secret from share points
    (x, y points on the polynomial).
    """
    if len(shares) < 2:
        raise ValueError("need at least two shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, 2**521 - 1)


p = remote("challenges1.hexionteam.com", 5001)
p.recvuntil(">>> ")
shares = []

for i in range(0x40):
    p.sendline(str(i))
    data = p.recvuntil(">>> ").replace(" ", "").replace("\n", "").replace(">>>", "")
    shares.append((bytes_to_long((str(i)).encode()), int(data)))

print(long_to_bytes(recover_secret(shares)))
```

Flag: `hexCTF{d0nt_us3_shar3s_lik3_that}`
