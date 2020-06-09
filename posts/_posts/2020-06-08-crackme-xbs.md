---
layout: post
title: Crackme - XBS
description: >
  Crackme challenge with radare2 and Z3 - The art of not using a decompiler
category: Binary Analysis
tags: radare2 gdb reversing
image: /assets/img/posts/crackme-xbs.png
---

# Crackme - XBS

## Table of contents

* list
{:toc}

## Target Binary

| Name           | Description                                               |
|----------------|-----------------------------------------------------------|
| File           | XBS (https://crackmes.one/crackme/5e604d4333c5d4439bb2dd72) |
| OS             | GNU/Linux                                            |
| Format         | ELF 64-bit LSB executable                                 |
| PIE            | Enabled                                                   |
| Symbol data    | Available                                                 |

**NOTE:** How to obtain file information is explained in previous posts ([stack5](./2020-05-09-protostar-stack5.md), [format4](./2020-06-01-protostar-format4.md)).

## Walkthrough

This challenge was downloaded from [crackmes.one](https://crackmes.one) and it is password zip protected. Typically, the password to unzip them is `crackmes.one`. Refer to the [FAQ](https://crackmes.one/faq) section of crackme.one

### Binary analysis

As first step, the binary was loaded into radare2. `aaaa` was used to 
perform a full analysis and function auto-naming. In order to understand the complexity of the binary, a good approach is to list the functions. `afl` can be used for this purpose:

```
[0x00001190]> afl
0x00001190    1 46           entry0
0x0000115e    1 40           sym._GLOBAL__sub_I_a
0x00001060    1 6            sym.imp.std::ios_base::Init::Init
0x000011c0    4 41   -> 34   sym.deregister_tm_clones
0x000011f0    4 57   -> 51   sym.register_tm_clones
0x00001230    5 65   -> 55   sym.__do_global_dtors_aux
0x00001280    1 9            entry.init0
0x00001000    3 27           sym._init
0x00001080   21 222          main
0x00001308    1 13           sym._fini
0x00001290    4 101          sym.__libc_csu_init
0x00001300    1 5            sym.__libc_csu_fini
0x00001030    1 6            sym.imp.__cxa_atexit
0x00001040    1 6            sym.imp.__stack_chk_fail
0x00001050    1 6            sym.imp.__isoc99_scanf
0x00001070    1 6            sym.imp.puts
```

The executable does not seem to have many functions. Besides `main`, it does not appear to be any other user-defined symbols. The next step is to understand the program flow, for this, the `main` function will be disassembled, as it regularly is the entry point of any executable, and in this case the most interesting symbol.

```
[0x00001080]> pdf
            ; DATA XREF from entry0 @ 0x11b1
            ;-- section..text:
            ;-- .text:
┌ 222: int main (char **envp, int64_t arg4);
│           ; var int64_t var_14h @ rsp+0x4
│           ; var int64_t canary @ rsp+0x8
│           ; arg char **envp @ rdx
│           ; arg int64_t arg4 @ rcx
│           0x00001080      53             push rbx                    ; [13] -r-x section size 645 named .text
│           0x00001081      31db           xor ebx, ebx
│           0x00001083      4883ec10       sub rsp, 0x10
│           0x00001087      64488b042528.  mov rax, qword fs:[0x28]
│           0x00001090      4889442408     mov qword [canary], rax
│           0x00001095      31c0           xor eax, eax
│           ; CODE XREF from main @ 0x110c
│       ┌─> 0x00001097      488d742404     lea rsi, [var_14h]
│       ╎   0x0000109c      488d3d610f00.  lea rdi, [0x00002004]       ; "%d" ; const char *format
│       ╎   0x000010a3      31c0           xor eax, eax
│       ╎   0x000010a5      e8a6ffffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│       ╎   0x000010aa      8b442404       mov eax, dword [var_14h]
│       ╎   0x000010ae      b91e000000     mov ecx, 0x1e
│       ╎   0x000010b3      31f6           xor esi, esi
│       ╎   0x000010b5      31d2           xor edx, edx
│       ╎   0x000010b7      4c8d05c22f00.  lea r8, obj.a               ; 0x4080
│       ╎   ; CODE XREF from main @ 0x10f3
│      ┌──> 0x000010be      4189c1         mov r9d, eax
│      ╎╎   0x000010c1      4863f9         movsxd rdi, ecx             ; arg4
│      ╎╎   0x000010c4      41d3f9         sar r9d, cl
│      ╎╎   0x000010c7      4180e101       and r9b, 1
│     ┌───< 0x000010cb      7422           je 0x10ef
│     │╎╎   0x000010cd      458b0c88       mov r9d, dword [r8 + rcx*4]
│     │╎╎   0x000010d1      4585c9         test r9d, r9d
│    ┌────< 0x000010d4      740a           je 0x10e0
│    ││╎╎   0x000010d6      ffc2           inc edx
│    ││╎╎   0x000010d8      4431c8         xor eax, r9d
│    ││╎╎   0x000010db      40b601         mov sil, 1
│   ┌─────< 0x000010de      eb0f           jmp 0x10ef
│   │││╎╎   ; CODE XREF from main @ 0x10d4
│   │└────> 0x000010e0      4084f6         test sil, sil
│   │┌────< 0x000010e3      7404           je 0x10e9
│   │││╎╎   0x000010e5      89442404       mov dword [var_14h], eax
│   │││╎╎   ; CODE XREF from main @ 0x10e3
│   │└────> 0x000010e9      418904b8       mov dword [r8 + rdi*4], eax
│   │┌────< 0x000010ed      eb0f           jmp 0x10fe
│   │││╎╎   ; CODE XREFS from main @ 0x10cb, 0x10de
│   └─└───> 0x000010ef      4883e901       sub rcx, 1                  ; arg4
│    │ └──< 0x000010f3      73c9           jae 0x10be
│    │  ╎   0x000010f5      4084f6         test sil, sil
│    │ ┌──< 0x000010f8      7404           je 0x10fe
│    │ │╎   0x000010fa      89442404       mov dword [var_14h], eax
│    │ │╎   ; CODE XREFS from main @ 0x10ed, 0x10f8
│    └─└──> 0x000010fe      ffca           dec edx                     ; envp
│      ┌──< 0x00001100      7f05           jg 0x1107
│      │╎   0x00001102      83fb01         cmp ebx, 1
│     ┌───< 0x00001105      7f2e           jg 0x1135
│     ││╎   ; CODE XREF from main @ 0x1100
│     │└──> 0x00001107      ffc3           inc ebx
│     │ ╎   0x00001109      83fb05         cmp ebx, 5
│     │ └─< 0x0000110c      7589           jne 0x1097
│     │     0x0000110e      488d056b2f00.  lea rax, obj.a              ; r8
│     │                                                                ; 0x4080
│     │     0x00001115      31d2           xor edx, edx
│     │     0x00001117      488d487c       lea rcx, [rax + 0x7c]
│     │     ; CODE XREF from main @ 0x1124
│     │ ┌─> 0x0000111b      0310           add edx, dword [rax]
│     │ ╎   0x0000111d      4883c004       add rax, 4
│     │ ╎   0x00001121      4839c8         cmp rax, rcx
│     │ └─< 0x00001124      75f5           jne 0x111b
│     │     0x00001126      488d3de50e00.  lea rdi, str.Congrats       ; 0x2012 ; "Congrats!"
│     │     0x0000112d      81fa38800140   cmp edx, 0x40018038
│     │ ┌─< 0x00001133      7407           je 0x113c
│     │ │   ; CODE XREF from main @ 0x1105
│     └───> 0x00001135      488d3dcb0e00.  lea rdi, str.Try_again      ; 0x2007 ; "Try again!"
│       │   ; CODE XREF from main @ 0x1133
│       └─> 0x0000113c      e82fffffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00001141      488b442408     mov rax, qword [canary]
│           0x00001146      64482b042528.  sub rax, qword fs:[0x28]
│       ┌─< 0x0000114f      7405           je 0x1156
│       │   0x00001151      e8eafeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x114f
│       └─> 0x00001156      4883c410       add rsp, 0x10
│           0x0000115a      31c0           xor eax, eax
│           0x0000115c      5b             pop rbx
└           0x0000115d      c3          
```

The `main` function is relatively extensive. But from a first look it is possible to determine some relevant information regarding to its inputs and outputs:

1. From address `0x0000109c` and `0x000010a5`, it can be appreciated that the program is requesting a signed integer from the standard input. Also based on the control flow indications shown by radare2, it seems that this could be called multiple times, as there is a jump instruction going back to `0x00001097`.
2. There are two outcomes from the program. It will either print "Congrats!" based on instruction `0x00001126` or will print "Try again!" as seen in `0x00001135`.

The next step is to understand how the input is used to generate a positive determination. Given the size and number of instructions, it can be cumbersome to analyze by just reading through the disassembly, to ease up the task, the general flow of the program can be traced down with the graph mode in radare2, by using `VV`.

```
┌───────────────────────────────────────────────────┐                                                     
│ [0x1080]                                          │                                                     
│ ;-- section..text:                                │                                                     
│ ;-- .text:                                        │                                                     
│ 0x00001080 [13] -r-x section size 645 named .text │                                                     
└───────────────────────────────────────────────────┘                                                     
     v                                                                                                     
     │                                                                                                     
     └──────┐                                                                                              
┌─────────────┐                                                                                            
│           │ │                                                                                            
│     ┌────────────────────────────────────────┐                                                           
│     │  0x1097 [oc]                           │                                                           
│     │ 0x0000109c const char *format          │                                                           
│     │ 0x000010a5 call sym.imp.__isoc99_scanf │                                                           
│     │ 0x000010b7 obj.a                       │                                                           
│     └────────────────────────────────────────┘                                                           
│         v                                                                                                
│         │                                                                                                
│         └───────────┐                                                                                    
│                     │ ┌────────────────────────────────┐                                                 
│                     │ │                                │                                                 
│               ┌────────────────────┐                   │                                                 
│               │  0x10be [od]       │                   │                                                 
│               │ 0x000010c1 arg4    │                   │                                                 
│               └────────────────────┘                   │                                                 
│                       f t                              │                                                 
│                       │ │                              │                                                 
│                       │ └────────────────────────────┐ │                                                 
│                   ┌───┘                              │ │                                                 
│               ┌────────────────────┐                 │ │                                                 
│               │  0x10cd [oe]       │                 │ │                                                 
│               └────────────────────┘                 │ │                                                 
│                     t f                              │ │                                                 
│                     │ │                              │ │                                                 
│      ┌──────────────┘ │                              │ │                                                 
│      │                └────────┐                     │ │                                                 
│      │                         │                     │ │                                                 
│  ┌────────────────────┐    ┌────────────────────┐    │ │                                                 
│  │  0x10e0 [og]       │    │  0x10d6 [of]       │    │ │                                                 
│  └────────────────────┘    └────────────────────┘    │ │                                                 
│          f t                   v                     │ │                                                 
│          │ │                   │                     │ │                                                 
│          │ │                   └───┐                 │ │                                                 
│          │ └─────────────┐         │                 │ │                                                 
│    ┌─────┘               │         │                 │ │                                                 
│    │                     │         │ ┌───────────────┘ │                                                 
│    │                     │         │ │                 │                                                 
│┌────────────────────┐    │   ┌────────────────────┐    │                                                 
││  0x10e5 [oh]       │    │   │  0x10ef [oj]       │    │                                                 
│└────────────────────┘    │   │ 0x000010ef arg4    │    │                                                 
│    v                     │   └────────────────────┘    │                                                 
│    │                     │         t f                 │                                                 
│    │                     │         │ │                 │                                                 
│    └─────┐               │         │ │                 │                                                 
│          │               │         └───────────────────┘                                                 
│          │ ┌─────────────┘       ┌───┘                                                                   
│          │ │                     │                                                                       
│    ┌────────────────────┐    ┌────────────────────┐                                                      
│    │  0x10e9 [oi]       │    │  0x10f5 [ok]       │                                                      
│    └────────────────────┘    └────────────────────┘    
│        v                             f t                                                                 
│        │                             │ │                                                                 
│        └──────────────┐              │ │                                                                 
│                       │              │ └───────────┐                                                     
│                       │      ┌───────┘             │                                                     
│                       │      │                     │                                                     
│                       │  ┌────────────────────┐    │                                                     
│                       │  │  0x10fa [ol]       │    │                                                     
│                       │  └────────────────────┘    │                                                     
│                       │      v                     │                                                     
│                       │      │                     │                                                     
│                       │      └─┐ ┌─────────────────┘                                                     
│                       └────────────┐                                                                     
│                                │ │ │                                                                     
│                          ┌────────────────────┐                                                          
│                          │  0x10fe [om]       │                                                          
│                          │ 0x000010fe envp    │                                                          
│                          └────────────────────┘                                                          
│                                  f t                                                                     
│                                  │ │                                                                     
│                                  │ └───────────────┐                                                     
│                              ┌───┘                 │                                                     
│                          ┌────────────────────┐    │                                                     
│                          │  0x1102 [on]       │    │                                                     
│                          └────────────────────┘    │                                                     
│                                  f t               │                                                     
│                                  │ │               │                                                     
│                                  │ └────┐          │                                                     
│                                  └────────────────┐│                                                     
│                                         │         │└┐                                                    
│                                         │         │ │                                                    
│                                         │   ┌────────────────────┐                                       
│                                         │   │  0x1107 [oo]       │                                       
│                                         │   └────────────────────┘                                       
│                                         │         t f                                                    
│                                         │         │ │                                                    
└───────────────────────────────────────────────────┘ │                                                    
                                          │       ┌───┘                                                    
                                          │   ┌────────────────────┐                                       
                                          │   │  0x110e [op]       │                                       
                                          │   │ 0x0000110e obj.a   │                                       
                                          │   └────────────────────┘                                       
                                          │       v                                                        
                                          │       │                                                        
                                          │   ┌───┘                                                        
                                          │   │                                                            
                                          │   │                                                            
                                          │   │                                                            
                                          │   └──────┐                                                     
                                         ┌─────────────┐                                                   
                                         ││          │ │                                                   
                                         ││    ┌────────────────────┐                                      
                                         ││    │  0x111b [oq]       │                                      
                                         ││    └────────────────────┘                                      
                                         ││            f t                                                 
                                         ││            │ │                                                 
                                         └───────────────┘                                                 
                                          │       ┌────┘                                                   
                                          │       │                                                        
                                          │   ┌─────────────────────────┐                                  
                                          │   │  0x1126 [or]            │                                  
                                          │   │ 0x00001126 str.Congrats │                                  
                                          │   └─────────────────────────┘  
                                          │           f t                                                  
                                          │           │ │                                                  
                                          │           │ └──┐                                               
                                 ┌────────│───────────┘    │                                               
                                 │ ┌──────┘                │                                               
                                 │ │                       │                                               
                           ┌──────────────────────────┐    │                                               
                           │  0x1135 [os]             │    │                                               
                           │ 0x00001135 str.Try_again │    │                                               
                           └──────────────────────────┘    │                                               
                               v                           │                                               
                               │                           │                                               
                               └────────┐                  │                                               
                                        │ ┌────────────────┘                                               
                                        │ │                                                                
                                  ┌──────────────────────────────┐                                         
                                  │  0x113c [ou]                 │                                         
                                  │ 0x0000113c call sym.imp.puts │                                         
                                  └──────────────────────────────┘                                         
                                          f t                                                              
                                          │ │                                                              
                                          │ └────────────────┐                                             
             ┌────────────────────────────┘                  │                                             
             │                                               │                                             
         ┌──────────────────────────────────────────┐    ┌───────────────────────┐                         
         │  0x1151 [ow]                             │    │  0x1156 [ox]          │                         
         │ 0x00001151 call sym.imp.__stack_chk_fail │    │ 0x0000115d sym._start │                         
         └──────────────────────────────────────────┘    └───────────────────────┘
```

In order to facilitate the understanding of the flow of the program, it is possible to abstract the control statements, into conditional and loop structures. The graph shows clearly the conditional statements that the function has, and how the flow is redirected. It is also clear that some of these conditional statements redirect the flow backward, resulting in loop structures. By analyzing the graph, it is possible to reduce it to pseudocode, like this:

**NOTE:** Codeblocks are represented by their address or label in square brackets. Conditions are represented as cond([block]), where `[block]` is the block containing the condition.

```
[0x1080]

while (condition(oo))
{
    [oc]

    while (condition(oj))
    {
        [od]

        if (condition(od))
        {
            [oj]
            continue   # oi redirects to start of loop
        }
        else
        {
            [oe]

            if (condition(oe))
            {
                [og]

                if (!condition(og)) # Only false executes additional block
                {
                    [oh]
                }
                [oi]
                goto [om]
            }
            else
            {
                [of]
                [oj]
                continue
            }
        }
    }

    [ok]
    if (!condition(ok)) # Only false executes additional block
    {
        [ol]
    }

    [om]
    if (!condition(om)) 
    {
        [on]
        if (condition(on))
        {
            goto [os] # Failure case
        }
        else 
        {
            [oo]
            continue 
        }
    }
    else
    {
        [oo]
        continue
    }
}

[op]

while (condition(oq))
{
    [oq]
}

[or] # This block accepts the input,
     # as this blocks sets the "Congrats" string

if (!condition(or)) # Only false path executes extra block
{
    [os] # This block fails the input, as this block sets
         # the "Try again" string
}

[ou]
```

Now that a base structure of the behavior of the program has been determined. It is possible to start unraveling the different code blocks and conditions the program executes.

This will be exemplified by unraveling the first three blocks:

Starting with `[0x1080]` block:

```
  ┌────────────────────────────────────────────┐                                                         
  │ [0x1080]                                   │                                                         
  │ ; [13] -r-x section size 645 named .text   │                                                         
  │   ; DATA XREF from entry0 @ 0x11b1         │                                                         
  │   ;-- section..text:                       │                                                         
  │   ;-- .text:                               │                                                         
  │ 222: int main (char **envp, int64_t arg4); │                                                         
  │ ; var int64_t var_14h @ rsp+0x4            │                                                         
  │ ; var int64_t canary @ rsp+0x8             │                                                         
  │ ; arg char **envp @ rdx                    │                                                         
  │ ; arg int64_t arg4 @ rcx                   │                                                         
  │ push rbx                                   │                                                         
  │ xor ebx, ebx                               │                                                         
  │ sub rsp, 0x10                              │                                                         
  │ mov rax, qword fs:[0x28]                   │                                                         
  │ mov qword [canary], rax                    │                                                         
  │ xor eax, eax                               │                                                         
  └────────────────────────────────────────────┘   
```

This block is mostly the function preamble (which will be ignored for the purposes of our pseudocode) and the initialization of variables. To ease the unraveling of the code blocks, an infix notation of the different instructions will be used to replace the blocks in the pseudocode.

In this case, the only relevant instructions would be `xor ebx, ebx` and `xor eax, eax`. XORing the same variable is equivalent to setting it to zero, the pseudocode would look like this:

```
ebx = 0
eax = 0

while (condition(oo))
{
    [oc]

    while (condition(oj))
    {
        ...
```

Next, the condition stated in `[oo]` will be added:

```
┌────────────────────────────────┐                     
│  0x1107 [oo]                   │                     
│ ; CODE XREF from main @ 0x1100 │                     
│ inc ebx                        │                     
│ cmp ebx, 5                     │                     
│ jne 0x1097                     │                     
└────────────────────────────────┘ 
```

The condition will be true, as long as ebx is not equal to 5.

```
ebx = 0
eax = 0

while (ebx != 5)
{
    [oc]

    while (condition(oj))
    {
        ...
```

Block `[oc]` is now added to the pseudocode:

```
 ┌──────────────────────────────────┐                                                           
 │  0x1097 [oc]                     │                    
 │ ; CODE XREF from main @ 0x110c   │                    
 │ lea rsi, [var_14h]               │                    
 │ ; const char *format             │                    
 │ ; "%d"                           │                    
 │ lea rdi, [0x00002004]            │                    
 │ xor eax, eax                     │                    
 │ ; int scanf(const char *format)  │                    
 │ call sym.imp.__isoc99_scanf;[ob] │                    
 │ mov eax, dword [var_14h]         │                    
 │ mov ecx, 0x1e                    │                    
 │ xor esi, esi                     │                    
 │ xor edx, edx                     │                    
 │ ; 0x4080                         │                    
 │ lea r8, obj.a                    │                    
 └──────────────────────────────────┘
```

```
ebx = 0
eax = 0

while (ebx != 5)
{
    scanf("%d", var_14h)
    eax = *var_14h
    ecx = 30
    esi = 0
    edx = 0
    r8 = obj.a

    while (condition(oj))
    {
        [od]
        ....

```

A similar procedure was followed for all the remaining blocks, producing the shown pseudocode:

```
ebx = 0
eax = 0

while (ebx != 5)
{
    scanf("%d", var_14h)
    eax = *var_14h
    ecx = 30
    esi = 0
    edx = 0
    r8 = obj.a

    while (rcx >= 0)
    {
        rd9 = eax
        rdi = ecx
        rd9 = rd9 >> cl         # cl is the lower 8 bits of rcx
        rd9 = rd9 & 1

        if (rd9 == 0)
        {
            rcx = rcx - 1       
            continue            # oi redirects to start of loop
        }
        else
        {
            rd9 = *(r8 + rcx * 4)

            if (rd9 == 0)
            {
                if (sil != 0) 
                {
                    *var_14 = eax
                }
                *(r8 + rcx * 4) = eax
                goto [om]
            }
            else
            {
                edx = edx + 1
                eax = eax ^ r9d
                sil = 1             # sil is the lower 8 bits of rsi
                rcx = rcx - 1
                continue
            }
        }
    }

    if (sil != 0) # Only false executes additional block
    {
        *var_14 = eax
    }

[om] :
    
    if (edx <= 1) 
    {
        if (ebx > 1)
        {
            goto [os] # Failure case
        }
        else 
        {
            ebx = ebx + 1
            continue 
        }
    }
    else
    {
        ebx = ebx + 1
        continue
    }
}

rax = obj.a
edx = 0
rcx = rax + 124

while (rax != rcx)
{
    edx = *rax
    rax = rax + 4
}

rdi = str.Congrats      # This block accepts the input,
                        # as this blocks sets the "Congrats" string

if (edx != 0x40018038) # Only false path executes extra block
{
[os]:
    rdi = str.Try_again      # This block fails the input, as this block sets
                             # the "Try again" string
}

puts(rdi)
```

This pseudocode is still verbose, further abstractions can be achieved by simplifying the expressions, removing irrelevant code and coalescing registers that represent the same variables.

After doing all of the above, the pseudocode results in:

```
ebx = 0
eax = 0

while (ebx != 5)
{
    scanf("%d", var_14h)
    eax = *var_14h
    ecx = 30
    edx = 0

    while (ecx >= 0)
    {
        rd9 = eax
        rd9 = rd9 >> ecx
        rd9 = rd9 & 1

        if (rd9 != 0)
        {
            rd9 = obj.a[ecx]

            if (rd9 == 0)
            {
                obj.a[ecx] = eax
                break
            }
            else
            {
                edx = edx + 1
                eax = eax ^ r9d
            }
        }
        ecx = ecx - 1  
    }

    if (edx <= 1 && ebx > 1)
    {
        goto [os] # Failure case
    }
    
    ebx = ebx + 1
}

rax = obj.a
edx = 0

while (rax != &obj.a[31])
{
    edx += *rax
    rax = rax + 4
}

rdi = str.Congrats      # This block accepts the input,
                        # as this blocks sets the "Congrats" string

if (edx != 0x40018038)  # Only false path executes extra block
{
[os]:
    rdi = str.Try_again      # This block fails the input, as this block sets
                             # the "Try again" string
}

puts(rdi)
```

From this, it is possible to understand that the executable will take a maximum of 5 signed integers. For each integer, it will test each of the bits by shifting right from 30 to 0. When a bit is set, it will try to store it in an array based on the index of the bit, if there was something already in that memory location the program will xor the stored value and the given value and assign it back to the current tested value. And for the last three integers given, at least 2 xor operations should have had happen, otherwise it will result in failure. Finally, the sum of all spaces in the array should result in 0x40018038, otherwise the program will fail as well.

### Creating a keygen

In order to construct an answer that is accepted by the program, it is required to generate the inverse function. Obtaining the inverse of a given function frequently proves difficult when dealing with arrays and bitwise operations. Fortunately, often these can be written as "[Constraint satisfaction problems](https://en.wikipedia.org/wiki/Constraint_satisfaction_problem)" or CSPs.

A CSP can be defined as a set of variables and constraints. In this case, the program is taking a set of objects (integers), applying operations over them and enforcing constraints on the calculated outputs. If the behavior of the program is represented as a CSP; some frameworks allow the extraction of models that satisfy the given problem.

One of the fields that is used to solve particular forms of CSPs, is the [satisfiability modulo theories](https://en.wikipedia.org/wiki/Satisfiability_modulo_theories) (SMT). Which solves decision problems for logical formulas based on the combinations of statements expressed in first-order logic. 

One popular SMT solver is [Z3](https://www.microsoft.com/en-us/research/blog/the-inner-magic-behind-the-z3-theorem-prover/), which was created by Microsoft. [Z3Py](https://ericpony.github.io/z3py-tutorial/guide-examples.htm) is a python library to use Microsoft's SMT theorem solver and will be used to create a key generator for the analyzed executable.

Describing an SMT problem is slightly different from regular imperative programming. As mentioned before, CSPs work by defining variables and constraints, so the programming approach is declarative, although python helps in generating the expressions through imperative statements.

SMT solvers are commonly used in binary analysis, more specifically for performing symbolic execution. Symbolic execution is a binary analysis technique and it is broadly used in practice to find vulnerabilities and bypasses in programs. Typically, when a program is executed, it uses concrete values for all the variables. At every instruction, every register and memory area contains a specific value and these values might change over time during the program's execution. However, symbolic execution allows to execute a given program without concrete values but using *symbols* or *symbolic values* instead; these can be seen as mathematical symbols that are used to model a targeted program.

There are some limitations in the way the SMT expressions can be written. For example control statement operations such as if statements or for loops cannot be expressed in SMT directly. In case of for loops, each declaration resulting from an iteration needs to be explicitly stated, this means that the number of iterations needs to be bounded (in this case python helps in automating the declarations with an actual `for` loop). On the other hand, if statements have to be represented slightly differently when defining an SMT problem. Expressions need to be expressed as assignments (which denotes the relationship of variables) or conditions (which denotes the constraints of the system). This means, that the if statements need to be translated to assignments, which can be done by transforming the if statements into (ternary operator assignations)["https://en.wikipedia.org/wiki/%3F:"] ; or into SMT constraints, if they are involved in the acceptation or rejection of the input.

Knowing this, we can adjust our pseudocode to reflect the proposed changes:

```
ebx = 0
eax = 0

while (ebx != 5)
{
    scanf("%d", var_14h)
    eax = *var_14h
    ecx = 30
    edx = 0

    while (ecx >= 0)
    {
        # These variables are declared here since they are modified in the 
        # below statements, and conditions are performed with the original
        # variables
        
        currentVar = eax
        currentArr = obj.a[ecx]
        
        obj.a[ecx] = currentVar >> ecx & 1 != 0 && currentArr == 0 ? currentVar : obj.a[ecx]
        
        # If the above is true, a break happens in the for statement
        # given the nature of the rules, this break cannot be expressed as
        # it is based on a variable of the SMT system. To simulate the break
        # eax is set to 0, as this will always make all the conditions 
        # inside the loop fail, rendering as no-ops
            
        eax = currentVar >> ecx & 1 != 0 && currentArr == 0 ? 0 : eax
        
        edx = currentVar >> ecx & 1 != 0 && currentArr != 0 ? edx + 1 : edx
        eax = currentVar >> ecx & 1 != 0 && currentArr != 0 ? currentVar ^ currentArr : eax

        ecx = ecx - 1  
    }

    constraint(!(edx <= 1 && ebx > 1))
    
    ebx = ebx + 1
}

rax = obj.a
edx = 0

while (rax != &obj.a[31])
{
    edx += *rax
    rax = rax + 4
}

constraint (edx == 0x40018038)  

```

By taking all these considerations, this pseudocode practically translates directly into a Z3Py script, that can be used to generate a model:

```python
from z3 import *

s = Solver()

x = [BitVec('x_%i'%i, 32) for i in range(0,5)]
arr = [BitVec('a_%i'%i, 32) for i in range(0,31)]

eax = BitVec('eax', 32)
edx = Int('edx')

currentArr = BitVec('ca', 32)
currentVar = BitVec('cv', 32)

i = 30
while i >= 0:
    arr[i] = 0
    i = i - 1

n = 0

while n < 5:

    eax = x[n]
    edx = 0
    i = 30
    bre = 0

    while i >= 0:
        currentArr = arr[i]
        currentVar = eax

        arr[i] = If(And (
                            ((currentVar >> i) & 1 ) == 1,
                            currentArr == 0
                        ),
                    currentVar,
                    arr[i]   
                )

        eax = If(And (
                    ((currentVar >> i) & 1 ) == 1,
                    currentArr == 0
                ),
            0,
            eax   
        )

        edx = If(And (
                            ((currentVar >> i) & 1 ) == 1,
                            currentArr != 0
                        ),
                    edx + 1,
                    edx   
                )

        eax = If(And (
                            ((currentVar >> i) & 1 ) == 1,
                            currentArr != 0
                        ),
                    currentVar ^ currentArr,
                    eax   
                )

        i = i - 1

    s.add(Not(And(edx <= 1, n > 1)))
    n = n + 1
    
s.add(sum(arr) == 1073840184)

while s.check() == sat:
    print(s.model()[x[0]], end = ' ')
    print(s.model()[x[1]], end = ' ')
    print(s.model()[x[2]], end = ' ')
    print(s.model()[x[3]], end = ' ')
    print(s.model()[x[4]])
    s.add(Or(x[0] != s.model()[x[0]], x[1] != s.model()[x[1]],
    x[2] != s.model()[x[2]], x[3] != s.model()[x[3]], x[4] != s.model()[x[4]])) 
```

Lists of Z3 variables were used to represent the inputs and the array used in the function. The `If` function was used to represent the ternary conditional operators defined in the previous step. A solver `s` was created to represent the SMT problem to be solved, to which the constraints were added through the `s.add` function. Finally, a solver will only give you a single model that satisfies the problem, in order to generate multiple solutions, a new constraint is added to prevent previous model values from being used in subsequent satisfiability checks, as seen in the last while loop.

When running the python script, it generates all possible solutions to the problem:

```sh
$ python3 ./z3test.py
130560 1073675264 1073676832 1073708512 1073677368
1906351744 3489619522 3489562333 1610571330 1342078602
4053835392 1342135874 1342078685 3758054978 1342078602
4054097536 1342135874 1342078685 3758054978 1342078602
4054097536 1342135874 1342078685 3758054982 1342078606
134217728 805306368 940121769 1073242509 805904043
2281701376 805306368 940121769 1073242509 805904043
2281701376 838860800 973676201 1073242509 839458475
2281701376 809500672 944316073 1073242509 810098347
2290089984 809500672 952704681 1073242509 810098347
142606336 809500672 952704681 1073242509 810098347
...
```

To prove this, the entries generated are passed to the original program:

```
PS /home/user/Downloads> "130560 1073675264 1073676832 1073708512 1073677368" | ./a.out
Congrats!
PS /home/user/Downloads> "1906351744 3489619522 3489562333 1610571330 1342078602" | ./a.out
Congrats!
PS /home/user/Downloads> "4053835392 1342135874 1342078685 3758054978 1342078602" | ./a.out
Congrats!
PS /home/user/Downloads> "4054097536 1342135874 1342078685 3758054978 1342078602" | ./a.out
Congrats!
PS /home/user/Downloads> "4054097536 1342135874 1342078685 3758054982 1342078606" | ./a.out
Congrats!
PS /home/user/Downloads> "134217728 805306368 940121769 1073242509 805904043" | ./a.out
Congrats!
PS /home/user/Downloads> "2281701376 805306368 940121769 1073242509 805904043" | ./a.out
Congrats!
PS /home/user/Downloads> "2281701376 838860800 973676201 1073242509 839458475" | ./a.out
Congrats!
PS /home/user/Downloads> "2281701376 809500672 944316073 1073242509 810098347" | ./a.out
Congrats!
PS /home/user/Downloads> "2290089984 809500672 952704681 1073242509 810098347" | ./a.out
Congrats!
PS /home/user/Downloads> "142606336 809500672 952704681 1073242509 810098347" | ./a.out
Congrats!

```
