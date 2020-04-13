# X0R - Solution

Created by Yarin ([GitHub](https://github.com/CmdEngineer) / [Twitter](https://twitter.com/CmdEngineer_))

## Description

XOR is best method for OTPs, especially for flags.

## Attached Files

```py
from random import choice, randint
from string import ascii_letters
from itertools import cycle

key = ''.join([choice(ascii_letters) for i in range(randint(8, 16))])

with open("flag.txt", "r") as file:
    flag = file.read()

key_gen = cycle(key)
data = []
for i in range(len(flag)):
    data.append(chr(ord(flag[i]) ^ ord(next(key_gen))))

with open("flag.enc", "w+") as file:
    file.write(''.join(data))
```

And an encrypted flag.

## Solution

We can use the known parts of the flag which are `hexCTF{` and the ending `}` ( I will ignore it though). To find part of the key because XOR is reversable.

Because the XOR is being cycled we can bruteforce the possible lengths to get possible solutions given our shorten key.

### Script

```py
from itertools import cycle

with open("flag.enc", "r") as file:
    data = file.read()

key = ""
for i in range(7):
    key += chr(ord("hexCTF{"[i]) ^ ord(data[i])) 

print("Known Key:", key)

for i in range(8, 17):
    filled_key = cycle(key + "\x00" * (i - len(key)))
    print(i, ''.join(c if c.isalpha() else "_" for c in [chr(ord(j) ^ ord(next(filled_key))) for j in data]))
```

### Output
> Known Key: JtmZzCJ
8 hexCTF__xN_ECXe__AFI_uY_tvIuv_y_eWbrS_H_CJ
9 hexCTF___percali__agilist__expiali__cious_
10 hexCTF_____kTAU_____NB_jDAn___yoByukc___CJ
11 hexCTF_____UMvuYI_____YDSX_lF____i_EsgAe__
12 hexCTF______soBypva_____tvIuv_y_____cious_
13 hexCTF_______Q_NPOhY______n_aGIXe______e_S
14 hexCTF________eWgoQPN_______Fi_AU_E_______
15 hexCTF_________i_XqiG_________yoByukc_____
16 hexCTF___________AFI_uY_________eWbrS_H___

We know the correct key length is 9 because it is the only one that makes sense:
`hexCTF{__percali__agilist__expiali__cious}`

At this point you can guess the flag or use google if you don't understand culture references.

Flag: `hexCTF{supercalifragilisticexpialidocious}`
