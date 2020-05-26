---
layout: post
title: Crackme - mgdilolmsoamasiug
description: >
  Crackme challenge with radare2 - The art of not using a decompiler
category: Binary Analysis
tags: radare2 gdb reversing
image: /assets/img/posts/crackme-mgdilolmsoamasiug.png
---

# Crackme - mgdilolmsoamasiug

## Table of contents

* list
{:toc}

## Target Binary

| Name           | Description                                               |
|----------------|-----------------------------------------------------------|
| File           | mgdilolmsoamasiug (https://crackmes.one/crackme/5e604d4333c5d4439bb2dd72) |
| OS             | GNU/Linux 3.2.0                                           |
| Format         | ELF 64-bit LSB executable                                 |
| PIE            | Enabled                                                   |
| Symbol data    | Available                                                 |

## Walkthrough

### Behaviour of the binary
This challenge was downloaded from [crackmes.one](https://crackmes.one) it is password zip protected. Typically, the password to unzip them is `crackmes.one`. Refer to the [FAQ](https://crackmes.one/faq) section of crackme.one

The first thing to be done when facing a binary reversing or binary exploitation challenge, is to execute it and see what it does at first instance (always do this on a contained environment for un-trusted binaries):

```sh
$ ./mgdilolmsoamasiug 
Input word: AAAAAAAAAA
Guess result: 10
Not exactly...
```

The program requires two string inputs, the ones prompted with `Input word` and `Guess result`. Since random inputs were given to the program, it printed `Not exactly`. The next step to be taken is to understand what condition makes the program print `Not exactly`.

For this challenge [radare2](https://rada.re/n/) was used to analyze the binary. Radare2 is a reverse-engineering framework that is typically used from the command line and it is composed of a set of utilities that can be used together or individually. 

### Patching the binary

The first and "cheating" approach to bypass a validation is to patch a binary. To patch a binary, the program should be loaded into radare2 with write permissions (`-w`):

```sh
$ r2 -w ./mgdilolmsoamasiug 
[0x000011e0]> 
```

**NOTE:** Since the original behavior of the binary will be altered it is advised to create a copy of it first.

In order to analyze the binary and be able to perform operations on it, such as finding cross references, one must analyze the binary, this is done through the `aaa` (analyze all, autoname functions) command:

```sh
[0x000011e0]> aaa
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

Then let's move to the main function using the seek (`s`) command:

```sh
[0x000011e0]> s main
[0x000012c9]> 
```

Notice how the address in the cursor changes from `0x000011e0` (program's entry point) to `0x000012c9` (program's main function).

It is time to find the string `Not exactly...` to understand what causes the program to output it. The command `iz` can be used to purge the strings of the binary:

```sh
[0x000012c9]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002005 0x00002005 12  13   .rodata ascii Input word: 
1   0x00002012 0x00002012 14  15   .rodata ascii Guess result: 
2   0x00002021 0x00002021 10  11   .rodata ascii Good job!\n
3   0x0000202c 0x0000202c 15  16   .rodata ascii Not exactly...\n
```

The`iz` command will not only show the strings but also the address where they are located.

Additionally, the command `axt` can be used to show cross references to an address. In this case, the string `Not exactly...` is being referenced at `0x000013e9`:

```
[0x000012c9]> axt 0x0000202c
main 0x13e9 [DATA] lea rsi, str.Not_exactly...
```

`s <address>` along with `pdf` instruction can be used to see the assembly around that address.

```sh
[0x000013e9]> s 0x13e9
[0x000013e9]> pdf ~..
...
│      └──> 0x000013bd      488d55a0       lea rdx, [var_60h]
│           0x000013c1      488d45c0       lea rax, [var_40h]
│           0x000013c5      4889d6         mov rsi, rdx
│           0x000013c8      4889c7         mov rdi, rax
│           0x000013cb      e838010000     call method __gnu_cxx::__enable_if<std::__is_char<char>::__value, bool>::__type std::operator==<char>(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) ; method.__gnu_cxx::__enable_if_std::__is_char_char_::__value__bool_::__type_std.operator___char__std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char____const___std::__cxx11::basic_string_char__std::char_traits_char___std::allocato
│           0x000013d0      84c0           test al, al
│       ┌─< 0x000013d2      7415           je 0x13e9
│       │   0x000013d4      488d35460c00.  lea rsi, str.Good_job       ; 0x2021 ; "Good job!\n"
│       │   0x000013db      488d3d3e2c00.  lea rdi, obj.std::cout      ; sym..bss
│       │                                                              ; 0x4020
│       │   0x000013e2      e869fdffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.imp.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const
│      ┌──< 0x000013e7      eb13           jmp 0x13fc
│      ││   ; CODE XREF from main @ 0x13d2
│      │└─> 0x000013e9      488d353c0c00.  lea rsi, str.Not_exactly... ; 0x202c ; "Not exactly...\n"
│      │    0x000013f0      488d3d292c00.  lea rdi, obj.std::cout      ; sym..bss
│      │                                                               ; 0x4020
│      │    0x000013f7      e854fdffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.imp.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const
│      │    ; CODE XREF from main @ 0x13e7
│      └──> 0x000013fc      bb00000000     mov ebx, 0

```

**NOTE:** You can pipe the output of the `pdf` command to `less` with the `~` radare modifier command and `..` to point to `less` as shown above.

From what is observed above, there is a jump equal `je` based on the result of `test al, al`. The `test` instruction performs a "bitwise and" between the operands and updates the `ZF` (Zero flag), `SF` (Sign flag), and `PF` (Parity flag). The `je` instruction jumps if the `ZF` is one, based on this, the only case where `je` is executed is if the value in `al` is 0.

The value in `al` is determined from the previous function call (as the function return value is stored in `rax` in x86-64 architectures). Radare2 resolved the symbol of the function that is called, which is the `==` operator of a `std::__cxx11::basic_string`.

**NOTE:** `al` represents the first byte of `rax`.

Determination of which string is printed is given by the `je` instruction, as stated above. In order to alter it and change the flow of the program, first radare2 needs to `seek` into the address containing the instruction. This is done through the `s` command.

```
[0x000012c9]>s 0x000013d2
[0x000013d2]> 

```

In order to confirm radare2 is pointing to the desired instruction, the print disassemble `pd` command can be used:

```
[0x000013d2]> pd 1
            0x000013d2      7415           je 0x13e9
[0x000013d2]> 
```

To modify the current instruction the `wao` (modify opcode) command is used. In order to reverse the jump condition (which is `je`), the oposite jump instruction `jnz` (jumps if zero flag is 0) is used.

```sh
[0x000013d2]> wao jnz
[0x000013d2]> pd1
            0x000013d2      7515           jne 0x13e9
[0x000013d2]> 
```

At this point, the program flow is already modified. To verify this, radare2 can be closed with the `q` command. Then the modified program is executed again, in this case it can be observed that the behavior is reversed.

```sh
[0x000013d2]> q
$ ./mgdilolmsoamasiug 
Input word: AAAAAAAAAA
Guess result: 10
Good job!
```

As seen above, the behavior of the binary was properly modified.

### Formal reversing

Most of the time in this type of challenges, the goal is to create a keygen or to understand how a program is validating a certain key. In this section, the binary in question will be reversed in order to understand how the program validates the inputs and gives a positive determination. Two approaches can be taken, static analysis or dynamic analysis.

#### Static analysis option

To start the static analysis, the original program will be loaded into radare2 with the following command:

```sh
$ radare2 ./mgdilolmsoamasiug
```

As mentioned in a previous section, it is important to analyze the binary using the command `aaa`:

```sh
[0x000011e0]> aaa
[Cannot analyze at 0x00001100g with sym. and entry0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[Cannot analyze at 0x00001100ac)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x000011e0]> 
```

In order to understand the general execution of the program, it is generally a good idea to disassemble the `main` function. To do this, the `main` function is sought with the `s` command, and then `VV` is used to enter visual mode.

```sh
[0x000013e9]> s main
[0x000012c9]> VV

```

Inside visual mode, it is possible to type `p` to change the visualization. One of the possible visualizations is a compressed flow diagram, which is useful to have a general notion of the branches in the program.

![](https://i.imgur.com/ELoFkFQ.png)

By looking at this graph, it is possible to see certain familiar structures such as conditional statements and loops. For example, the block tagged with `[od]` finishes in a conditional statement which when true goes to block `[of]` otherwise to `[oe]`. Or the block `[oc]` jumps back to block `[ob]` which performs a condition, this could be a sign of a loop block.

Another interesting piece of information is the lines observed in the`[0x12c9]` block. This block contains the function signature and the local variables defined in the current stack frame.

As mentioned in the previous section, the program determines if a good input was given by the condition stored in `0x000013d2`. From the previous diagram it can be observed that this statement is stored in the block `[od]` (As the block starts with instruction 0x13bd, indicated in the block itself, and finishes before the start of the next block, which the start address is 0x13d4).

As explained in the previous section, this determination was done by the result of the `==` operand of an `std::__cxx11::basic_string` type.

To continue the analysis, backtracking of the arguments given to the compare operator will be done. To achieve it, the block `[od]` is analyzed:

```sh
[0x000013bd]> s 0x13bd
[0x000013bd]> pD (0x13d4 - 0x13bd)
           ; CODE XREF from main @ 0x1365
           0x000013bd      488d55a0       lea rdx, [var_60h]
           0x000013c1      488d45c0       lea rax, [var_40h]
           0x000013c5      4889d6         mov rsi, rdx
           0x000013c8      4889c7         mov rdi, rax
           0x000013cb      e838010000     call method __gnu_cxx::__enable_if<std::__is_char<char>::__value, bool>::__type std::operator==<char>(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)
           0x000013d0      84c0           test al, al
           0x000013d2      7415           je 0x13e9

```

**NOTE:** `pD` command can be used to disassemble the next N bytes.

By looking at the disassembly of the block, it is possible to determine that the arguments passed to the `==` operand are `var_60h` and `var_40h`. Since these are stored in the registers `rsi` and `rdi` just before the `call` instruction is performed. In x86-64 instead of storing all the arguments of a function in the top of the stack, the first 6 arguments are stored in predefined registers. RDI and RSI are used for the first and second arguments. More information can be found [here](http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html).

Now that the variables involved in the condition were identified, the next step is understanding the values that are being compared. To do this, an analysis of the blocks preceding the comparison will be inspected.

The top block of the function graph will be analyzed first:

```sh
[0x00000096]> s 0x12c9
[0x000012c9]> pD (0x135f - 0x12c9)
            ; DATA XREF from entry0 @ 0x1201
 367: int main (int argc, char **argv, char **envp);
           ; var int64_t var_68h @ rbp-0x68
           ; var signed int64_t var_64h @ rbp-0x64
           ; var int64_t var_60h @ rbp-0x60
           ; var int64_t var_40h @ rbp-0x40
           ; var int64_t canary @ rbp-0x18
           0x000012c9      f30f1efa       endbr64
           0x000012cd      55             push rbp
           0x000012ce      4889e5         mov rbp, rsp
           0x000012d1      53             push rbx
           0x000012d2      4883ec68       sub rsp, 0x68
           0x000012d6      64488b042528.  mov rax, qword fs:[0x28]
           0x000012df      488945e8       mov qword [canary], rax
           0x000012e3      31c0           xor eax, eax
           0x000012e5      488d45a0       lea rax, [var_60h]
           0x000012e9      4889c7         mov rdi, rax
           0x000012ec      e89ffeffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string() ; sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string
           0x000012f1      488d45c0       lea rax, [var_40h]
           0x000012f5      4889c7         mov rdi, rax
           0x000012f8      e893feffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string() ; sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string
           0x000012fd      488d35010d00.  lea rsi, str.Input_word:    ; 0x2005 ; "Input word: "
           0x00001304      488d3d152d00.  lea rdi, obj.std::cout      ; sym..bss
                                                                      ; 0x4020
           0x0000130b      e840feffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.imp.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const
           0x00001310      488d45a0       lea rax, [var_60h]
           0x00001314      4889c6         mov rsi, rax
           0x00001317      488d3d222e00.  lea rdi, obj.std::cin       ; 0x4140
           0x0000131e      e84dfeffff     call sym std::basic_istream<char, std::char_traits<char> >& std::operator>><char, std::char_traits<char>, std::allocator<char> >(std::basic_istream<char, std::char_traits<char> >&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) ; sym.imp.std::basic_istream_char__std::char_traits_char_____std::operator___char__std::char_traits_char___std::allocator_char____std::basic_istream_char__std::char_traits_char______std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char
           0x00001323      488d35e80c00.  lea rsi, str.Guess_result:  ; 0x2012 ; "Guess result: "
           0x0000132a      488d3def2c00.  lea rdi, obj.std::cout      ; sym..bss
                                                                      ; 0x4020
           0x00001331      e81afeffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.imp.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const
           0x00001336      488d45c0       lea rax, [var_40h]
           0x0000133a      4889c6         mov rsi, rax
           0x0000133d      488d3dfc2d00.  lea rdi, obj.std::cin       ; 0x4140
           0x00001344      e827feffff     call sym std::basic_istream<char, std::char_traits<char> >& std::operator>><char, std::char_traits<char>, std::allocator<char> >(std::basic_istream<char, std::char_traits<char> >&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&) ; sym.imp.std::basic_istream_char__std::char_traits_char_____std::operator___char__std::char_traits_char___std::allocator_char____std::basic_istream_char__std::char_traits_char______std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char
           0x00001349      488d45a0       lea rax, [var_60h]
           0x0000134d      4889c7         mov rdi, rax
           0x00001350      e84bfeffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::length() const ; sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::length___const
           0x00001355      89459c         mov dword [var_64h], eax
           0x00001358      c74598000000.  mov dword [var_68h], 0
```

The variables of interest `var_40h` and `var_60h` are pointers to `std::__cxx11::basic_string`, which are allocated in `0x000012ec` and `0x000012f8` respectively.

Next the program uses `basic_ostream` operator `<<` to print the string "Input word: " followed by `basic_istream` operator `>>` to store the stdin given in variable `var_60h`.

A similar process was done for "Guess result: " string and variable `var_40h`.

Based on the previous statements, it is known that at this point in the execution `var_60h` will hold the first string passed and `var_40h` will hold the second one.

At the end of this block, `var_64h` is assigned with the length of the string stored in `var_60h` and 0 is stored into `var_68h`.

Next step in the analysis is to understand block `[ob]` and `[oc]`. As mentioned earlier, these blocks seem to form a loop structure, this can be clearly seen in `[ob]` disassembly:

```sh
[0x000012c9]> s 0x135f
[0x0000135f]> pD (0x1367 - 0x135f)
           ; CODE XREF from main @ 0x13bb
           0x0000135f      8b4598         mov eax, dword [var_68h]
           0x00001362      3b459c         cmp eax, dword [var_64h]
           0x00001365      7d56           jge 0x13bd
[0x0000135f]> 
```

From the top block of the main function it is known that `var_68h` holds 0 and `var_64h` holds the length of the string stored in `var_60h`. The disassembly previously shown, does a comparison between these two variables and jumps when `var_68h` is greater or equal to `var_64h`. 

**NOTE:** `cmp` performs a subtraction of the operands given, and updates the `ZF`, `SF`, `PF` and `OF` (Overflow flag). `jge` (Jump greater of equal) instruction will jump to the given address if the `SF` and `OF` are set.

The above assembly looks like a for loop from 0 to the length of the string. When `var_68h` reaches the length of the string (stored in `var_60h`) the execution jumps to `[od]`, otherwise it executes the code in block `[oc]`. By analyzing block `[oc]` it is possible to appreciate that this is actually the case.

```sh
[0x0000135f]> s 0x1367
[0x00001367]> pD (0x13bd - 0x1367)
   0x00001367      8b4598         mov eax, dword [var_68h]
   0x0000136a      4863d0         movsxd rdx, eax
   0x0000136d      488d45a0       lea rax, [var_60h]
   0x00001371      4889d6         mov rsi, rdx
   0x00001374      4889c7         mov rdi, rax
   0x00001377      e854feffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::operator[](unsigned long) ; sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::operator___unsigned_long
   0x0000137c      4889c3         mov rbx, rax
   0x0000137f      8b4598         mov eax, dword [var_68h]
   0x00001382      4863d0         movsxd rdx, eax
   0x00001385      488d45a0       lea rax, [var_60h]
   0x00001389      4889d6         mov rsi, rdx
   0x0000138c      4889c7         mov rdi, rax
   0x0000138f      e83cfeffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::operator[](unsigned long) ; sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::operator___unsigned_long
   0x00001394      0fb600         movzx eax, byte [rax]
   0x00001397      0fbec0         movsx eax, al
   0x0000139a      99             cdq
   0x0000139b      f77d9c         idiv dword [var_64h]
   0x0000139e      89d0           mov eax, edx
   0x000013a0      4863d0         movsxd rdx, eax
   0x000013a3      488d45a0       lea rax, [var_60h]
   0x000013a7      4889d6         mov rsi, rdx
   0x000013aa      4889c7         mov rdi, rax
   0x000013ad      e81efeffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::operator[](unsigned long) ; sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::operator___unsigned_long
   0x000013b2      0fb613         movzx edx, byte [rbx]
   0x000013b5      8810           mov byte [rax], dl
   0x000013b7      83459801       add dword [var_68h], 1
   0x000013bb      eba2           jmp 0x135f
```

By looking at the variables involved in the code block, two main takeaways can be appreciated right away. The first one: `var_68h` is increased by one at the end of the block and `var_64h` is unmodified, confirming that this is indeed a for loop with increments of 1. The second: the contents of variable `var_60h` are modified inline inside the code block. This means that the program determination is done by comparing the unmodified contents of `var_40h` (a string inputted after "Guessed result: " is printed) and a modified version of `var_60h` which originally contained the string inputted by the user after "Input word: " was shown.

To understand how the contents of `var_60h` are modified, the assembly of this codeblock is analyzed in depth (note that function calls were re-written for better visibility):

```sh
0x00001367   mov eax, dword [var_68h]           ; eax = *dword(var_68h)
0x0000136a   movsxd rdx, eax                    ; rdx = eax (with sign extension)
0x0000136d   lea rax, [var_60h]                 ; rax = var_60h (pointer to string)
0x00001371   mov rsi, rdx                       ; rsi(arg1) = *dword(var_68h)
0x00001374   mov rdi, rax                       ; rdi(arg0) = var_60h (pointer to string)
0x00001377   call sym basic_string::operator[]  ; rax = &var_60h[*dword(var_68h)]
0x0000137c   mov rbx, rax                       ; rbx = rax = &var_60h[*dword(var_68h)]
0x0000137f   mov eax, dword [var_68h]           ; eax = *dword(var_68h)
0x00001382   movsxd rdx, eax                    ; rdx = eax (with sign extension) 
0x00001385   lea rax, [var_60h]                 ; rax = var_60h (pointer to string)
0x00001389   mov rsi, rdx                       ; rsi(arg1) = *dword(var_68h)
0x0000138c   mov rdi, rax                       ; rdi(arg0) = var_60h (pointer to string)
0x0000138f   call sym basic_string::operator[]  ; rax = &var_60h[*dword(var_68h)]
0x00001394   movzx eax, byte [rax]              ; eax = *byte(var_60h[var_68h]) (Zero-Extend)
0x00001397   movsx eax, al                      ; eax = lsb(eax) (Sign extend)
0x0000139a   cdq                                ; extend to quad
0x0000139b   idiv dword [var_64h]               ; (integer divide) remainder (dx) : quoitiend (ax) = eax / var_64h
0x0000139e   mov eax, edx                       ; eax = dx (remainder)
0x000013a0   movsxd rdx, eax                    ; rdx = dx (remainder)
0x000013a3   lea rax, [var_60h]                 ; rax = var_60h
0x000013a7   mov rsi, rdx                       ; rsi = dx (remainder)
0x000013aa   mov rdi, rax                       ; rdi = var_60h
0x000013ad   call sys basic_string::operator[]  ; rax = &var_60h[dx (remainder)]
0x000013b2   movzx edx, byte [rbx]              ; edx = *byte(var_60h[var_68h])
0x000013b5   mov byte [rax], dl                 ; var_60h[dx (remainder)] = var_60h[var_68h]
0x000013b7   add dword [var_68h], 1             ; var_68h ++
0x000013bb   jmp 0x135f                         ; loop again
```

A high-level view of the code block would be:
1. The character stored in the position `var_68h` of string `var_60h` is extracted.
2. This character is treated as an integer and divided by the length of the string.
3. The residue of the division is used as the index of `var_60h` to store the character that resides in `var_60h[var_68h]`

It is possible to further summarize the codeblock as this expression:

```
var_60h[var_60h[var_68h % length] = var_60h[var_68h];
```

After this block is over, the next block `[od]` does the determination if the input satisfies the criteria of the program by comparing the modified `var_60h` and the second string given to the program in `var_40h`.

In order to generate valid inputs, the following powershell script was written:

```sh
Function Get-ModifiedString($String)
{
    $StringA = $string.ToCharArray()
    
    for ($i = 0; $i -lt $string.Length; $i++)
    {
        $pos = [int]$StringA[$i] % $string.Length
        $StringA[$pos] = $StringA[$i]
    }

    for ($i = 0; $i -lt $string.Length; $i++)
    {
        Write-Host -NonewLine $StringA[$i]
    }
}   
```

The following input was generated to prove that the binary was reversed and understood correctly:

```sh
PS /home/user/Downloads> Get-ModifiedString "thisisarandomstring"
rsasisarghiomsmnong
```

When given to the program, it is observed that the input satisfies the condition:

```sh
$ ./mgdilolmsoamasiug 
Input word: thisisarandomstring
Guess result: rsasisarghiomsmnong
Good job!
```

#### Dynamic analysis option

To enter debugger mode in radare2, one should type the command `ood`:

```sh
[0x000012c9]>
[0x000012c9]> ood
Process with PID 30006 started...
= attach 30006 30006
File dbg:///home/user/Documents/mgdilolmsoamasiug  reopened in read-write mode
30006
[0x7f68184ab090]> 
```

Or with the flag `-d` to open radare2 in debugger mode from the beginning:

```sh
$ radare2 -d ./mgdilolmsoamasiug
```

radare2 debugger does not start at the entry point of the binary as many other debuggers do (like GDB or Windbg). Instead, radare2 debugger is a low-level debugger (like OllyDbg) that starts at the binary's loader. To move to `main` the program needs to continue its execution until it hits the main function:

```sh
[0x7f68184ab090]> dcu main
Continue until 0x5632fb8632c9 using 1 bpsize
hit breakpoint at: 5632fb8632c9
```

`dcu` will set a breakpoint in the specified function or address, in this case in `main` (debugger continue until main).

```sh
> pdf
            ; DATA XREF from entry0 @ 0x5588a0f41201
            ;-- rax:
 367: int main (int argc, char **argv, char **envp);
           ; var int64_t var_68h @ rbp-0x68
           ; var int64_t var_64h @ rbp-0x64
           ; var int64_t var_60h @ rbp-0x60
           ; var int64_t var_40h @ rbp-0x40
           ; var int64_t var_18h @ rbp-0x18
           0x5588a0f412c9      f30f1efa       endbr64
           0x5588a0f412cd      55             push rbp
           0x5588a0f412ce      4889e5         mov rbp, rsp
           0x5588a0f412d1      53             push rbx
           ;-- rip:
           0x5588a0f412d2      4883ec68       sub rsp, 0x68
           0x5588a0f412d6      64488b042528.  mov rax, qword fs:[0x28]
           0x5588a0f412df      488945e8       mov qword [var_18h], rax
           0x5588a0f412e3      31c0           xor eax, eax
           0x5588a0f412e5      488d45a0       lea rax, [var_60h]
           0x5588a0f412e9      4889c7         mov rdi, rax
           0x5588a0f412ec      e89ffeffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string() ; sym.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string
           0x5588a0f412f1      488d45c0       lea rax, [var_40h]
           0x5588a0f412f5      4889c7         mov rdi, rax
           0x5588a0f412f8      e893feffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string() ; sym.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string
           0x5588a0f412fd      488d35010d00.  lea rsi, str.Input_word: ; 0x5588a0f42005 ; "Input word: "
           0x5588a0f41304      488d3d152d00.  lea rdi, reloc.std::cout_32 ; 0x5588a0f44020 ; "`91\xed\x8e\x7f"
           0x5588a0f4130b      e840feffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const
           0x5588a0f41310      488d45a0       lea rax, [var_60h]
...
```

The string entered by the user after the `Input word:`  prompt is stored in `var_60h` and the string entered by the user after `Guess result:` is prompt, is stored in `var_40h`.

The following strings were inputted:

```
Input word: ABCD
Guess result: whatever
```

It is possible to confirm it by examining the content of those variables by using `afvd`:

```sh
:> afvd
var var_18h = 0x7ffe74b7e108 = (qword)0xcb4e3f7968405d00
var var_60h = 0x7ffe74b7e0c0 = (qword)0x00007ffe74b7e0d0
var var_40h = 0x7ffe74b7e0e0 = (qword)0x00007ffe74b7e0f0
var var_64h = 0x7ffe74b7e0bc = (qword)0x74b7e0d0000055ba
var var_68h = 0x7ffe74b7e0b8 = (qword)0x000055baa75f34ac
```

And printing the content of those variables:

```sh
:> px 8 @0x00007ffe74b7e0d0
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffe74b7e0d0  7e41 4243 4400 0000                      ~ABCD... ;Content of var_60h
```

```sh
:> px 10 @0x00007ffe74b7e0f0
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffe74b7e0f0  7e77 6861 7465 7665 7200                 ~whatever. ;Content of var_40h
```

After that, the length of the word is calculated and stored in `var_64h` :

```sh
0x55baa75f3350      e84bfeffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::length() const ; sym.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::length___const
0x55baa75f3355      89459c         mov dword [var_64h], eax
```

**Note:** *In x86-64, the value returned by a function is stored in rax.*

Something interesting about radare2 is the visual mode, which allows users to see the control flow graph of the loaded program. To enter visual mode the command `VV` was used. Use the arrow keys to navigate. It is possible to see that a set of three instructions are particularly interesting in one of the blocks. These three instructions together typically translate into a while/for loop:

```sh
mov
cmp
jge or jle
```

If the visual mode is changed to a summarized control graph view (pressing `p` 2 times while in Visual mode) it is possible to see that while the iterator `var_68h` is less than the size of the first string that was entered to the program. 

![](https://i.imgur.com/xLBH8Gh.png)

*Summarized control flow graph:*

![](https://i.imgur.com/kKymCo4.png)


Those instructions could be translated as:

```python
while iterator <= sizeOfString{
    doWork;
}
```
While debugging the content of the `while` loop, it is possible to see interesting operations that are being performed to the first string that was given to the program. It divides the `ascii` value of the first character in the first string given as input and then it stores the reminder on `rdx`:

```sh
0x55baa75f339b      f77d9c         idiv dword [var_64h]
0x55baa75f339e      89d0           mov eax, edx
0x55baa75f33a0      4863d0         movsxd rdx, eax
0x55baa75f33a3      488d45a0       lea rax, [var_60h]
0x55baa75f33a7      4889d6         mov rsi, rdx
0x55baa75f33aa      4889c7         mov rdi, rax
```
The operation to obtain the reminder of a division is also called `modulo operation`:

$$
0x41\ \%\ 4 = 1
$$

**NOTE:** It is possible to evaluate expressions on radare2 as well:

```sh
:> ? 0x41 % 4 ;Char A = 0x41 & "ABCD" length is 4
int32   1
uint32  1
hex     0x1
octal   01
unit    1
...
```

Then, it is going to replace the character stored in the index corresponding to the result of the modulo operation with the character stored in the current index.

$$
index = int(string[i]) \%\ size \\
string[index] = string[i]
$$

In this example, the letter at index 1 is the letter "B" of the original string(`ABCD`)

```
Original string:
ABCD
Modified string after the first replacement:
AACD
```

After that, it is going to increment the iterator (`var_68`) by 1:

```sh
0x55baa75f33b7      83459801       add dword [var_68h], 1
```

To confirm this, the values of `var_68h` were printed before and after the `add` instruction.

Before the add instruction:

```sh
:> afvd
...
var var_68h = 0x7ffcf8c6c408 = (qword)0x0000000900000000
```

After the add instruction:

```sh
:> afvd
...
var var_68h = 0x7ffcf8c6c408 = (qword)0x0000000900000001
```

The program is going to repeat the same process with the entire string; until the iterator is greater than or equal to the string size (As shown previously on the control flow graph). Finally, when it finishes traversing the entire string, the program will compare the modified string with the string entered as "Guessed value". If they are both the same, the program will print `Good job!`. In this example, the "Guessed value" was `whatever`. Since the strings won't match the program will print `Not exactly!`: 

```sh
0x55baa75f33bd      488d55a0       lea rdx, [var_60h]
           0x55baa75f33c1      488d45c0       lea rax, [var_40h]
           0x55baa75f33c5      4889d6        mov rsi, rdx
           0x55baa75f33c8      4889c7         mov rdi, rax
           0x55baa75f33cb      e838010000     call sym __gnu_cxx::__enable_if<std::__is_char<char>::__value, bool>::__type std::operator==<char>(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) ; sym.__gnu_cxx::__enable_if_std::__is_char_char_::__value__bool_::__type_std::operator___char__std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char____const___std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char____const
           0x55baa75f33d0      84c0           test al, al
       ┌─< 0x55baa75f33d2      7415           je 0x55baa75f33e9
       │   0x55baa75f33d4      488d35460c00.  lea rsi, str.Good_job   ; 0x55baa75f4021 ; "Good job!\n"
       │   0x55baa75f33db      488d3d3e2c00.  lea rdi, reloc.std::cout_32 ; 0x55baa75f6020 ; "`\x99\x93\xf1\r\x7f"
       │   0x55baa75f33e2      e869fdffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const
       |   0x55baa75f33e7      eb13           jmp 0x55baa75f33fc
       └─> 0x55baa75f33e9      488d353c0c00.  lea rsi, str.Not_exactly... ; 0x55baa75f402c ; "Not exactly...\n"
          0x55baa75f33f0      488d3d292c00.  lea rdi, reloc.std::cout_32 ; 0x55baa75f6020 ; "`\x99\x93\xf1\r\x7f"
          0x55baa75f33f7      e854fdffff     call sym std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) ; sym.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const
```

To solve this challenge, it is required to reproduce the algorithm used by the program to scramble the first string. This, to introduce any string and then introduce the modified string as the "guessed value" for the program to give a favorable determination and print `Good job!`. Since now the algorithm to scramble the original string is known, a python script was created to reproduce it and solve the challenge:


```python
def solver(str_input):
    string = list(str_input)

    size = len(string)

    i = 0
    new_index = 0

    while i < size:
        new_index = ord(string[i]) % size
        string[new_index] = string[i]
        i = i + 1

    print(*string, sep='')


if __name__ == '__main__':
    str_input  = input("Enter a string:" )
    solver(str_input)

```

After executing the script, the modified string is obtained and can be used to solve the challenge:

```sh
$ python3 ./crackme_solver.py
Enter a string:ABCD
AACC
```

If the program is run again using those values, the challenge would have been solved:

```sh
$ ./mgdilolmsoamasiug 
Input word: ABCD
Guess result: AACC
Good job!
```

Other string values were tested as well to prove the solver works. I.e. `whatever` was used as input to the solver and the string resulted satisfied the program check:

```sh
$ python3 ./crackme_solver.py
Enter a string:whatever
haattvvw
```

```sh
Input word: whatever
Guess result: haattvvw
Good job!
```

### Side challenge

As part of the crackme description, the author invites to guess the original name of the executable. This section approaches how the possible solution was found.

First, the string of the program was passed to our solution generator:

```sh
PS /home/user/Downloads> Get-ModifiedString "mgdilolmsoamasiug" 
mgdilolmsoamasidg
```

This did not bear any results, as the outputted string does not look like a name.

The reverse operation probably needs to be performed on the string. Due to the nature of the operation done by the program, there is no one-one correlation between the input and output. Since multiple inputs can produce the same output. Take the example of "ab" "ad":

```sh
PS /home/user/Downloads> Get-ModifiedString "ab"               
aa     
PS /home/user/Downloads> Get-ModifiedString "ad"
aa      
```

By analyzing the properties of the operation, it can be known if a given character in the string was modified if the following condition is true:

```
modifiedString[currentIndex] % length == currentIndex
```

Knowing this, it is possible to determine which are the unmodified characters of the string to be analyzed. The following script was done to automate the determination:

```sh
Function Get-ProbableSolutions($string)
{
    $StringA = $string.ToCharArray()
    $Changed = @()
    for ($i = 0; $i -lt $string.Length; $i++)
    {
        $pos = [int]$StringA[$i] % $string.Length
        $Changed = $Changed + @([int]($pos -eq $i))
    }

    Write-Host $string

    for ($i = 0; $i -lt $string.Length; $i++)
    {
        Write-Host -NonewLine ($Changed[$i])
    }
}
```

By giving the name of the executable, this script outputs 1 if a character was modified or 0 if it was not.

```sh
PS /home/user/Downloads> Get-ProbableSolutions "mgdilolmsoamasiug"
mgdilolmsoamasiug
01010011010011010
```

Another interesting property is that for every index containing a modified character, if the character stored in the given index is present in the left subarray, it means that the value contained in the original string was overwritten before it was evaluated. Therefore, it is irrelevant for the generation of the target string, and originally it could have had any character value, since it is always overwritten before it is evaluated. Eg. given an original string "adbcx", when operating over it the character 'a' will overwrite the index 2 of the string (as 'a' % 5 is 2), so the original value of index 2 ('b') will never be evaluated, therefore irrelevant for the inverse operation.

The previous script was modified to look for this property as well. A new row of 0/1 will be printed denoting if that index of the array can map to any character value in a possible original string.

```sh
Function Get-ProbableSolutions($string)
{
    $StringA = $string.ToCharArray()

    # Was the value changed?
    $Changed = @()

    # Was the value overwritten before evaluation?
    $CharactersEncountered = @{}
    $CharacterThatCanHoldAnyValue =  @()

    for ($i = 0; $i -lt $string.Length; $i++)
    {
        $pos = [int]$StringA[$i] % $string.Length
        $Changed = $Changed + @([int]($pos -eq $i))

        # Was it modified by a previous encountered character?
        if ($CharactersEncountered.ContainsKey($StringA[$i]) -and ($pos -eq $i))
        {
            $CharacterThatCanHoldAnyValue = $CharacterThatCanHoldAnyValue + @(1) # Mark as yes
        }
        else
        {
            $CharactersEncountered[$StringA[$i]] = 1
            $CharacterThatCanHoldAnyValue = $CharacterThatCanHoldAnyValue + @(0) # Mark as no
        }
    }

    Write-Host $string

    for ($i = 0; $i -lt $string.Length; $i++)
    {
        Write-Host -NonewLine ($Changed[$i])
    }
    Write-Host ""
    for ($i = 0; $i -lt $string.Length; $i++)
    {
        Write-Host -NonewLine ($CharacterThatCanHoldAnyValue[$i])
    }
}
```

By analyzing the filename string again, the following result is shown:

```sh
PS /home/user/Downloads> Get-ProbableSolutions "mgdilolmsoamasiug"
mgdilolmsoamasiug
01010011010011010                      
00000011010011000
```

At this point, the only values to be determined are of the characters that were overwritten after they were evaluated in the original operation. The values stored in these indexes can only be characters contained in the final string or characters that have eclipsing counterparts in the right subarray (Ex. in a length 5 array 'A' and 'F' value are eclipsing each other as both divided by 5 have a 0 residue).

Additionally, it is necessary to take into consideration the set of values that appear in the modified indexes, but not in the unmodified indexes. These values were contained in modified indexes before they were overwritten, as these values had to come from some index in the original string. 

In our case the M(Characters in modified indexes) and U(Characters in unmodified indexes):

$$
M = \{g, i, l, m, o, a, s, u\} \\ 
U = \{m, d, l, o, s ,a ,n ,i, g\} \\
M\ U = \{u\}
$$

Knowing all these properties, the possible original strings will have these restrictions:

|Index|Character| Modified? | Set of possible original characters           |
|-----|---------|-----------|-----------------------------------------------|
|0    |m        | NO        | m                                             |
|1    |g        | YES       | {g,d,i,l,o,m,s,a,u} or eclipsing counterparts of right subarray |
|2    |d        | NO        | d                                             |
|3    |i        | YES       | {g,d,i,l,o,m,s,a,u} or eclipsing counterparts of right subarray |
|4    |l        | NO        | l                                             |
|5    |o        | NO        | o                                             |
|6    |l        | YES       | any character                                 |
|7    |m        | YES       | any character                                 |
|8    |s        | NO        | x                                             |
|9    |o        | YES       | any character                                 |
|10   |a        | NO        | a                                             |
|11   |m        | NO        | m                                             |
|12   |a        | YES       | any character                                 |
|13   |s        | YES       | any character                                 |
|14   |i        | NO        | i                                             |
|15   |u        | YES       | any character                                 |
|16   |g        | NO        | g                                             | 

And:
$$
string[1] ==\ 'u'\ |\ string[3] ==\ 'u'\ |\ string [15] ==\ 'u'
$$

By making an educated guess based on these restrictions a possible answer could be:

"moduloissoamazing"

By inputting this to the program along with its name, it accepts the answer.

```sh
$ ./mgdilolmsoamasiug 
Input word: moduloissoamazing                                                                    
Guess result: mgdilolmsoamasiug
Good job!     
```
