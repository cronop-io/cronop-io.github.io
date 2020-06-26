---
layout: post
title: Instrumenting a Chess game with FRIDA
description: >
  Instrumenting dreamchess for Linux to play against StockFish, the famous chess engine. 
category: Binary Analysis
tags: radare2 gdb reversing frida instrumentation
image: /assets/img/posts/dreamchess_frida.png
---

# Instrumenting a Chess game with FЯIDA

## Table of contents

* list
{:toc}

In this entry the open-source [DreamChess](https://www.dreamchess.org/) [[LICENSE](https://github.com/dreamchess/dreamchess/blob/master/LICENSE.txt)] game will be reversed and instrumented with [Frida](https://frida.re/). The goal is to simulate a human playing against the game CPU by intercepting the binary's function calls and leveraging existing byte code to input moves. The human agent is simulated through a well known open source chess engine called [StockFish](https://stockfishchess.org/). For this exercise, the binary was reversed as if there is no knowledge of the source code. 

## Requirements

Tools were installed in a Ubuntu machine version 5.4.0-37-generic.

| Name           | Description                                          | Install                                                             |
| -------------- | ---------------------------------------------------- | ------------------------------------------------------------------- |
| Frida          | Binary instrumentation tool.                         | pip3 install frida-tools                                             |
| Radare2        | Reverse engineering framework and command-line tools  | Clone & build. [Instructions](https://github.com/radareorg/radare2) |
| Dreamchess     | Chess game to be instrumented.                       | sudo apt-get install dreamchess                                     |
| StockFish      | Chess engine to simulate the human playing the game. | sudo apt-get install stockfish                                      |
| StockFish PyPI | Python wrapper for StockFish.                        | pip install stockfish                                               |

## Static binary analysis

The first step is to understand the characteristics of our target binary (dreamchess). To analyze, radare2 will be used. The binary was loaded, and the basic info was dumped:

```
[0x0000be00]> iI
arch     x86
baddr    0x0
binsz    210516
bintype  elf
bits     64
canary   true
class    ELF64
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  false
lsyms    false
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      true
relocs   false
relro    full
rpath    NONE
sanitiz  false
static   false
stripped true
subsys   linux
va       true
```

During this analysis, the important aspects to note are the architecture and if the binary has been stripped. Architecture can give us an idea of the [ABI](https://en.wikipedia.org/wiki/Application_binary_interface) which determines the calling convention, and if the binary has been stripped it means that there is no debug information that can aid during debugging and reversing. Unfortunately in this case, as most production binaries, debug symbols have been stripped.

**NOTE:** A description of all the attributes output by `iI` can be found [here](https://dzhy.dev/2020/02/28/Understanding-rabin2-output/).

The next step in the analysis process is to visualize the functions the binary possess. This will help identify calls that can be intercepted to know the state of the board, and that can be used to introduce input to the program. To do this `afl` was used in radare2.
 
```sh
0x0000be00]> afl
0x0000be00    1 46           entry0
0x000242c0   27 335  -> 318  sym.move_selector
0x0001a2e0    1 120          sym.gg_scrollbarv_create
0x00027440    1 9            sym.pipe_unix_exit
0x000277c0    3 60   -> 53   sym.msgbuf_exit
0x0000ab90    1 11           sym.imp.free
0x0001ae90    1 14           sym.gg_system_draw_char
0x00023890    1 183          sym.start_piece_move
0x0000b380    1 11           sym.imp.SDL_GetTicks
...
0x0001a610    1 94           sym.gg_seperatorh_create
0x00025ab0    1 11           sym.get_black_in_check
0x0001b460   21 839  -> 815  sym.gg_vbox_input
0x0001a8c0    1 16           sym.gg_signal_exit
...
0x00020f40    4 145  -> 140  fcn.00020f40
0x00020fe0    4 107  -> 102  fcn.00020fe0
0x00021050    4 85   -> 80   fcn.00021050
0x00021590    4 75           fcn.00021590
0x00022910    1 89           fcn.00022910
0x00023020    6 259  -> 254  fcn.00023020
0x00022970   64 1359 -> 1310 fcn.00022970
```

Interestingly, even though the binary was stripped there are plenty of functions that map into named symbols. This is because, even though symbols were stripped, these functions are being exported by the binary resulting in this information being exposed. 

As observed with radare2 previously, and with objdump. There are no debug symbols:

```sh
$ objdump --syms /usr/games/dreamchess 

/usr/games/dreamchess:     file format elf64-x86-64

SYMBOL TABLE:
no symbols
```

Although, if the exports are listed, it is possible to observe the functions detected by radare2:

```sh
$ objdump -TC /usr/games/dreamchess 

/usr/games/dreamchess:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*    0000000000000000  GLIBC_2.2.5 wait
0000000000000000      DF *UND*    0000000000000000  GLIBC_2.2.5 strdup
0000000000000000      DF *UND*    0000000000000000              XML_SetUserData
0000000000000000      DF *UND*    0000000000000000              glClearDepth
0000000000000000      DF *UND*    0000000000000000  GLIBC_2.2.5 select
0000000000000000      DF *UND*    0000000000000000              glTexCoord2fv
0000000000000000      DF *UND*    0000000000000000  GLIBC_2.14  memcpy
0000000000000000      DF *UND*    0000000000000000              XML_ParserFree
0000000000000000      DF *UND*    0000000000000000  GLIBC_2.7   __isoc99_sscanf
0000000000000000      DF *UND*    0000000000000000              SDL_SetWindowFullscreen
0000000000000000      DF *UND*    0000000000000000              glScalef
0000000000000000      DF *UND*    0000000000000000              glMatrixMode
0000000000000000      DF *UND*    0000000000000000  GLIBC_2.2.5 realloc
0000000000000000      DF *UND*    0000000000000000              glHint
...
```

This is not necessarily a programmer mistake, since there are cases where it is desired to export the functions so other programs can link against and reuse the functionality. But usually executables hide their exports by compiling with `-fvisibility=hidden`. More information on this can be found [here](http://gcc.gnu.org/wiki/Visibility).

This will ease when looking for functions of interest. As an initial naive approach, the export list will be filtered to find functions that contain keywords such as board, move, and game. Since these can give us hints on how a game is created, the board is configured and how to detect movements of the pieces on the board. Which will help instrumenting the binary later on.

Filter exports with "board":
```
[0x0000be00]> iE ~board
163 0x0000b430 GLOBAL FUNC       SDL_GetKeyboardState
192  0x00026590 0x00026590 GLOBAL FUNC   30       get_saved_board
283  0x0000c660 0x0000c660 GLOBAL FUNC   272      board_setup
284  0x00023c00 0x00023c00 GLOBAL FUNC   48       load_board
303  0x000260a0 0x000260a0 GLOBAL FUNC   608      dialog_vkeyboard_create
331  0x00026090 0x00026090 GLOBAL FUNC   11       get_vkeyboard_enabled
399  0x00025a40 0x00025a40 GLOBAL FUNC   12       get_board
625  0x00026070 0x00026070 GLOBAL FUNC   22       toggle_vkeyboard_enabled
```

Filter exports with "move":
```
[0x0000be00]> iE ~move
166  0x000242c0 0x000242c0 GLOBAL FUNC   335      move_selector
170  0x00023890 0x00023890 GLOBAL FUNC   183      start_piece_move
195  0x0000e2b0 0x0000e2b0 GLOBAL FUNC   31       game_get_move_list
212  0x0000c770 0x0000c770 GLOBAL FUNC   217      move_to_fullalg
226  0x0001de50 0x0001de50 GLOBAL FUNC   820      draw_move_lists
254  0x0000de90 0x0000de90 GLOBAL FUNC   54       game_move_now
272  0x0000ded0 0x0000ded0 GLOBAL FUNC   47       game_want_move
314  0x0000dfc0 0x0000dfc0 GLOBAL FUNC   120      game_make_move
321  0x0000cc50 0x0000cc50 GLOBAL FUNC   486      move_set_attr
332  0x0000cfa0 0x0000cfa0 GLOBAL FUNC   584      move_to_san
390  0x0000c850 0x0000c850 GLOBAL FUNC   338      make_move
417  0x00024240 0x00024240 GLOBAL FUNC   123      move_camera
424  0x0000e1c0 0x0000e1c0 GLOBAL FUNC   231      game_make_move_str
435  0x0001d650 0x0001d650 GLOBAL FUNC   1055     get_move
448  ---------- 0x00038bc0 GLOBAL OBJ    8        move
480  ---------- 0x00038ba0 GLOBAL OBJ    28       san_move
486  0x0000ce40 0x0000ce40 GLOBAL FUNC   351      fullalg_to_move
525  0x0000de30 0x0000de30 GLOBAL FUNC   89       game_retract_move
564  0x0000c9b0 0x0000c9b0 GLOBAL FUNC   134      move_is_valid
607  0x0000d1f0 0x0000d1f0 GLOBAL FUNC   98       san_to_move
```

Filter exports with "game":

```
[0x0000be00]> iE ~game
195  0x0000e2b0 0x0000e2b0 GLOBAL FUNC   31       game_get_move_list
249  0x00015110 0x00015110 GLOBAL FUNC   12       get_ingame_style
250  0x00013a50 0x00013a50 GLOBAL FUNC   615      dialog_ingame_create
254  0x0000de90 0x0000de90 GLOBAL FUNC   54       game_move_now
272  0x0000ded0 0x0000ded0 GLOBAL FUNC   47       game_want_move
314  0x0000dfc0 0x0000dfc0 GLOBAL FUNC   120      game_make_move
374  0x0000dd40 0x0000dd40 GLOBAL FUNC   110      game_view_prev
424  0x0000e1c0 0x0000e1c0 GLOBAL FUNC   231      game_make_move_str
458  0x0000dfb0 0x0000dfb0 GLOBAL FUNC   11       game_get_engine_error
469  0x0000dfa0 0x0000dfa0 GLOBAL FUNC   11       game_set_engine_error
493  0x0000dcb0 0x0000dcb0 GLOBAL FUNC   137      game_view_next
523  0x0000e050 0x0000e050 GLOBAL FUNC   360      game_load
525  0x0000de30 0x0000de30 GLOBAL FUNC   89       game_retract_move
552  0x0000ddb0 0x0000ddb0 GLOBAL FUNC   118      game_undo
582  0x0000e040 0x0000e040 GLOBAL FUNC   15       game_quit
606  0x0000df00 0x0000df00 GLOBAL FUNC   150      game_save
617  0x00025a90 0x00025a90 GLOBAL FUNC   11       get_game_stalemate
620  0x000215e0 0x000215e0 GLOBAL FUNC   1264     dialog_title_newgame_create
```

This approach has been fruitful. As some functions look promising, such as `make_move`, `get_board`, `game_load`, etc. 

Also, there are some other functions, not necessarily related to the movement of the pieces or configuration, such as `san_to_move` that are interesting as well, as they include terms related to chess programming. In this particular one, `san` probably refers to the [standard algebraic notation](https://en.wikipedia.org/wiki/Algebraic_notation_(chess)), which can help translate internal structures to a human-readable form.

## Dynamic binary analysis

Since some functions of interest have already been detected, it is possible to move to a dynamic approach. In this phase [`frida-trace`](https://frida.re/docs/frida-trace/) will be used to understand when different functions of interest are being called.

### Determining piece movements

In order to instrument the binary to play by itself, knowledge of how the program moves the pieces is required. As these calls need to be intercepted when the CPU issues a move and issued when the external engine that simulates the human responding.

To determine this, the program will be interacted with during a chess game session while `frida-trace` is running while filtering for function calls with `move`.

The following command was issued to start tracing:

```sh
$ frida-trace  -i *move* dreamchess
...
62 ms  get_move()
63 ms  game_want_move()
69 ms  draw_move_lists()
69 ms     | game_get_move_list()
78 ms  get_move()
78 ms  game_want_move()
82 ms  draw_move_lists()
...
```

Many function calls are being printed constantly, even without user interaction, probably due to the UI calling these while refreshing the screen. These functions will be excluded from the trace to isolate the ones being called only during user interaction. Resulting in the following command line:

```
frida-trace -i *move*  -x *get_move -x *game_want_move -x *draw_move_lists -x *game_get_move_list -x *_dbus_list_remove_link dreamchess
```

When the CPU moves a piece, it generates the following trace:

```
Started tracing 226 functions. Press Ctrl+C to stop.                    
           /* TID 0x974a */
  8091 ms  san_to_move()
  8091 ms  fullalg_to_move()
  8091 ms     | move_is_valid()
  8091 ms     |    | make_move()
  8091 ms     | move_set_attr()
  8091 ms     |    | make_move()
  8091 ms     |    | move_is_valid()
  8091 ms     |    | move_is_valid()

```

This was achieved by starting a game where the CPU plays as whites (plays first).

![](https://i.imgur.com/tD5yNu5.png)

Now the inverse will be done. A new chess game will be started where the user plays the first move.

After the first piece is move, it is possible to see the following trace:

```
 23874 ms  game_make_move()
 23874 ms     | move_is_valid()
 23874 ms     |    | make_move()
 23874 ms     | move_set_attr()
 23874 ms     |    | make_move()
...
```

![](https://i.imgur.com/Rsd9D9t.png)

By comparing these two, it is possible to see that `san_to_move` is called only when the CPU issues a move, and `game_make_move` when the human moves.

#### Identifying CPU piece movements

The next step is to identify when a CPU movement is completed. So when instrumenting the binary a callback can be set to respond to the movement issued by the game. 

To understand this, a GDB session will be attached to the game process, and as a starting point, a breakpoint will be set in `san_to_move` as this function is only called during CPU piece movements.

```
$ ps -au | grep dreamchess
     38730  360  2.4 2136836 196628 pts/3  Rl+  Jun19 7076:14 /usr/games/dreamchess
     49888  0.0  0.5  59264 40352 pts/2    S+   11:12   0:02 r2 /usr/games/dreamchess
     52224  0.0  0.0  17664   736 pts/5    S+   13:45   0:00 grep --color=auto dreamchess
$ gdb -pid 38730
...
b san_to_move
```

By doing multiple moves, it is possible to appreciate that only when the CPU starts a movement this breakpoint is hit, inline to what is observed with `frida-trace`. 

Although by the end of the execution of this function call, the piece is not yet moved on the board. This can be appreciated by hitting the breakpoint and continuing to the end of the function by issuing a `fin` gdb command.

![](https://i.imgur.com/RIDTj8S.png)

Additional to this, it seems that the function is directly called from `main`, as seen in the image above. In order to understand when a move is finalized, `main` will be disassembled around `san_to_move` function call, to understand the next steps the program is taking and analyze them dynamically with GDB to appreciate when a CPU movement is completed.

To ease the disassembly, radare2 was used:

```
[0x0000b460]> axt sym.san_to_move
main 0xbb92 [CALL] call sym.san_to_move
sym.game_make_move_str 0xe22b [CALL] call sym.san_to_move
[0x0000bb92]> s 0xbb92
[0x0000bb92]> pd 40
│      ╎╎   0x0000bb92      e859160000     call sym.san_to_move
│      ╎╎   0x0000bb97      488b7c2408     mov rdi, qword [dest]
│      ╎╎   0x0000bb9c      4885c0         test rax, rax
│      ╎╎   0x0000bb9f      4989c7         mov r15, rax
│     ┌───< 0x0000bba2      7421           je 0xbbc5
│     │╎╎   ; CODE XREF from main @ 0xbbd3
│    ┌────> 0x0000bba4      31ff           xor edi, edi
│    ╎│╎╎   0x0000bba6      e8f5730000     call sym.audio_play_sound
│    ╎│╎╎   0x0000bbab      4c89ff         mov rdi, r15                ; int64_t arg1
│    ╎│╎╎   0x0000bbae      be01000000     mov esi, 1                  ; int64_t arg2
│    ╎│╎╎   0x0000bbb3      e888200000     call fcn.0000dc40
│    ╎│╎╎   0x0000bbb8      4c89ff         mov rdi, r15                ; void *ptr
│    ╎│╎╎   0x0000bbbb      e8d0efffff     call sym.imp.free           ; void free(void *ptr)
│    ╎│└──< 0x0000bbc0      e90bfdffff     jmp 0xb8d0
│    ╎│ ╎   ; CODE XREF from main @ 0xbba2
│    ╎└───> 0x0000bbc5      4c89f6         mov rsi, r14
│    ╎  ╎   0x0000bbc8      e873120000     call sym.fullalg_to_move
│    ╎  ╎   0x0000bbcd      4989c7         mov r15, rax
│    ╎  ╎   0x0000bbd0      4885c0         test rax, rax
│    └────< 0x0000bbd3      75cf           jne 0xbba4
│       ╎   0x0000bbd5      4c89f1         mov rcx, r14
│       ╎   0x0000bbd8      488d15a1ca01.  lea rdx, str.Failed_to_parse_move_string___s ; 0x28680 ; "Failed to parse move string '%s'"
│       ╎   0x0000bbdf      be38020000     mov esi, 0x238
│       ╎   0x0000bbe4      31c0           xor eax, eax
│       ╎   0x0000bbe6      488d3d2bca01.  lea rdi, str.build_dreamchess_2gtGVK_dreamchess_0.3.0_dreamchess_src_dreamchess.c ; 0x28618 ; "/build/dreamchess-2gtGVK/dreamchess-0.3.0/dreamchess/src/dreamchess.c"
│       ╎   0x0000bbed      e80e190000     call sym.dbg_error
│       └─< 0x0000bbf2      e9d9fcffff     jmp 0xb8d0
...
```

There are a couple of familiar functions in this disassembly. For example, after calling `san_to_move` the binary might jump to `0x0000bbc5` where `fullalg_to_move` is called, similar to what was observed in `frida-trace`. Then, when successful, it jumps back and executes from instruction `0x0000bba4` and calls into `audio_play_sound` and `fcn.0000dc40`. 

As an initial approach gdb will be used to single-step through main after the execution of `san_to_move`.

```
Thread 1 "dreamchess" hit Breakpoint 1, 0x000055852612c1f0 in san_to_move ()
(gdb) fin
Run till exit from #0  0x000055852612c1f0 in san_to_move ()
0x000055852612ab97 in main ()
(gdb) si
0x000055852612ab9c in main ()
(gdb) si
0x000055852612ab9f in main ()
(gdb) si
0x000055852612aba2 in main ()
(gdb) si
0x000055852612abc5 in main ()
(gdb) si
0x000055852612abc8 in main ()
(gdb) si
0x000055852612be40 in fullalg_to_move ()
(gdb) fin
Run till exit from #0  0x000055852612be40 in fullalg_to_move ()
0x000055852612abcd in main ()
(gdb) si
0x000055852612abd0 in main ()
(gdb) si
0x000055852612abd3 in main ()
(gdb) si
0x000055852612aba4 in main ()
(gdb) si
0x000055852612aba6 in main ()
(gdb) si
0x0000558526131fa0 in audio_play_sound ()
(gdb) fin
Run till exit from #0  0x0000558526131fa0 in audio_play_sound ()
0x000055852612abab in main ()
(gdb) si
0x000055852612abae in main ()
(gdb) si
0x000055852612abb3 in main ()
(gdb) si
0x000055852612cc40 in ?? ()
(gdb) fin
Run till exit from #0  0x000055852612cc40 in ?? ()
0x000055852612abb8 in main ()
```

At the end of the function `0x000055852612cc40`, the piece was finally moved. This function corresponds to `fcn.0000dc40` mentioned above. This can be proved by subtracting the offset of the module to the function address:

```
(gdb) info proc map 
process 38730
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x55852611f000     0x558526129000     0xa000        0x0 /usr/games/dreamchess
...
(gdb) p/x 0x000055852612cc40 - 0x55852611f000
$1 = 0xdc40
```

As seen above the offset matches to what radare2 indicated as function name. 

As the next step, this call will be monitored with `frida-trace`, to understand when it is called. 

```
frida-trace -a dreamchess\!0xdc40 dreamchess
```

By interacting with the system. It seems that this function is called any time a piece is moved from either side (human, CPU). 

![](https://i.imgur.com/wUN0Ipm.png)

This function can be intercepted to know when a move is completed. Afterward, based on the ordering of the moves, it is possible to determine if the move was done by the CPU or the human.

#### Initiating moves

The next step is to find a function that can be instrumented to send moves to the program. This to simulate the human playing against the machine.

From the initial `frida-trace`, it was determined that every time a user moves a piece the function `game_make_move` was called. Based on the name it seems to be a way of issuing piece movements.

By using gdb it is possible to call functions defined in the binary, although these might require arguments. To find if they do, and what they might be, radare2 can be used to both disassemble the function and find cross-references that indicate the usage.

As an initial step, radare2 will be used to dissasemble the function:

```
[0x000247c0]> s sym.game_make_move
[0x0000dfc0]> pdf
       ╎╎   ; CALL XREF from sym.game_make_move_str @ 0xe23e
       ╎╎   ; CALL XREF from fcn.00024660 @ 0x24840
┌ 115: sym.game_make_move (int64_t arg1);
│      ╎╎   ; arg int64_t arg1 @ rdi
│      ╎╎   0x0000dfc0      f30f1efa       endbr64
│      ╎╎   0x0000dfc4      55             push rbp
│      ╎╎   0x0000dfc5      4889fd         mov rbp, rdi                ; arg1
│      ╎╎   0x0000dfc8      e873fcffff     call fcn.0000dc40
│      ╎╎   0x0000dfcd      85c0           test eax, eax
│     ┌───< 0x0000dfcf      7427           je 0xdff8
│     │╎╎   0x0000dfd1      488b05486602.  mov rax, qword [0x00034620] ; [0x34620:8]=0
│     │╎╎   0x0000dfd8      486315496602.  movsxd rdx, dword [0x00034628] ; [0x34628:4]=0
│     │╎╎   0x0000dfdf      488d3df4d601.  lea rdi, [0x0002b6da]       ; "%s\n"
│     │╎╎   0x0000dfe6      5d             pop rbp
│     │╎╎   0x0000dfe7      488b74d0f8     mov rsi, qword [rax + rdx*8 - 8]
│     │╎╎   0x0000dfec      31c0           xor eax, eax
│     │└──< 0x0000dfee      e9edf2ffff     jmp sym.comm_send
..
│     │ ╎   ; CODE XREF from sym.game_make_move @ 0xdfcf
│     └───> 0x0000dff8      488b05196602.  mov rax, qword [0x00034618] ; [0x34618:8]=0
│       ╎   0x0000dfff      4889ee         mov rsi, rbp
│       ╎   0x0000e002      488b4010       mov rax, qword [rax + 0x10]
│       ╎   0x0000e006      488b7810       mov rdi, qword [rax + 0x10]
│       ╎   0x0000e00a      e861e7ffff     call sym.move_to_fullalg
│       ╎   0x0000e00f      488d3d02a601.  lea rdi, str.build_dreamchess_2gtGVK_dreamchess_0.3.0_dreamchess_src_dreamchess.c ; 0x28618 ; "/build/dreamchess-2gtGVK/dreamchess-0.3.0/dreamchess/src/dreamchess.c" ; int64_t arg1
│       ╎   0x0000e016      be08010000     mov esi, 0x108              ; int64_t arg2
│       ╎   0x0000e01b      488d156da401.  lea rdx, str.Ignoring_illegal_move__s ; 0x2848f ; "Ignoring illegal move %s" ; int64_t arg3
│       ╎   0x0000e022      4889c5         mov rbp, rax
│       ╎   0x0000e025      4889c1         mov rcx, rax                ; int64_t arg4
│       ╎   0x0000e028      31c0           xor eax, eax
│       ╎   0x0000e02a      e811f6ffff     call sym.dbg_warn
│       ╎   0x0000e02f      4889ef         mov rdi, rbp
│       ╎   0x0000e032      5d             pop rbp
└       └─< 0x0000e033      e958cbffff     jmp sym.imp.free
```

Radare2 already shows the signature that it expects the function to have`sym.game_make_move (int64_t arg1);`). By going through the function, it seems to be calling the function `fcn.0000dc40` mentioned in the previous section. This further indicates that `game_make_move` could be the function used by the user to initiate a move.

Cross references of `game_make_move` can help understanding the parameter that it receives:

```
[0x0000dfc0]> axt sym.game_make_move
sym.game_make_move_str 0xe23e [CALL] call sym.game_make_move
fcn.00024660 0x24840 [CALL] call sym.game_make_move
```

By looking at `game_make_move_str` dissasemble it is possible to know how `game_make_move` is called:

```
[0x0000d1f0]> s sym.game_make_move_str
[0x0000e1c0]> pdf
            ; CALL XREF from sym.yyparse @ 0x10e3e
┌ 228: sym.game_make_move_str (int64_t arg1, int64_t arg2);
│           ; var int64_t var_30h @ rsp+0x138
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           0x0000e1c0      f30f1efa       endbr64
│           0x0000e1c4      4156           push r14
│           0x0000e1c6      488d1512a301.  lea rdx, str.Parsing_move_string___s ; 0x284df ; "Parsing move string '%s'"
│           0x0000e1cd      b926000000     mov ecx, 0x26               ; '&'
│           0x0000e1d2      4155           push r13
│           0x0000e1d4      4189f5         mov r13d, esi               ; arg2
│           0x0000e1d7      4154           push r12
│           0x0000e1d9      4989fc         mov r12, rdi                ; arg1
│           0x0000e1dc      55             push rbp
│           0x0000e1dd      4881ec480100.  sub rsp, 0x148
│           0x0000e1e4      64488b042528.  mov rax, qword fs:[0x28]
│           0x0000e1ed      488984243801.  mov qword [var_30h], rax
│           0x0000e1f5      31c0           xor eax, eax
│           0x0000e1f7      488b051a6402.  mov rax, qword [0x00034618] ; [0x34618:8]=0
│           0x0000e1fe      4889e7         mov rdi, rsp
│           0x0000e201      4989e6         mov r14, rsp
│           0x0000e204      488b4010       mov rax, qword [rax + 0x10]
│           0x0000e208      488b7010       mov rsi, qword [rax + 0x10]
│           0x0000e20c      31c0           xor eax, eax
│           0x0000e20e      f348a5         rep movsq qword [rdi], qword ptr [rsi]
│           0x0000e211      4c89e1         mov rcx, r12
│           0x0000e214      be39010000     mov esi, 0x139
│           0x0000e219      488d3df8a301.  lea rdi, str.build_dreamchess_2gtGVK_dreamchess_0.3.0_dreamchess_src_dreamchess.c ; 0x28618 ; "/build/dreamchess-2gtGVK/dreamchess-0.3.0/dreamchess/src/dreamchess.c"
│           0x0000e220      e85bf5ffff     call sym.dbg_log
│           0x0000e225      4c89e6         mov rsi, r12                ; int64_t arg2
│           0x0000e228      4c89f7         mov rdi, r14                ; int64_t arg1
│           0x0000e22b      e8c0efffff     call sym.san_to_move
│           0x0000e230      4889c5         mov rbp, rax
│           0x0000e233      4885c0         test rax, rax
│       ┌─< 0x0000e236      7438           je 0xe270
│       │   ; CODE XREF from sym.game_make_move_str @ 0xe281
│      ┌──> 0x0000e238      4889ef         mov rdi, rbp
│      ╎│   0x0000e23b      4489ee         mov esi, r13d
│      ╎│   0x0000e23e      e87dfdffff     call sym.game_make_move
│      ╎│   0x0000e243      4889ef         mov rdi, rbp                ; void *ptr
│      ╎│   0x0000e246      e845c9ffff     call sym.imp.free           ; void free(void *ptr)
│      ╎│   ; CODE XREF from sym.game_make_move_str @ 0xe2a0
│     ┌───> 0x0000e24b      488b84243801.  mov rax, qword [var_30h]
│     ╎╎│   0x0000e253      644833042528.  xor rax, qword fs:[0x28]
│    ┌────< 0x0000e25c      7544           jne 0xe2a2
│    │╎╎│   0x0000e25e      4881c4480100.  add rsp, 0x148
│    │╎╎│   0x0000e265      5d             pop rbp
│    │╎╎│   0x0000e266      415c           pop r12
│    │╎╎│   0x0000e268      415d           pop r13
│    │╎╎│   0x0000e26a      415e           pop r14
│    │╎╎│   0x0000e26c      c3             ret
..
│    │╎╎│   ; CODE XREF from sym.game_make_move_str @ 0xe236
│    │╎╎└─> 0x0000e270      4c89e6         mov rsi, r12                ; char *s
│    │╎╎    0x0000e273      4c89f7         mov rdi, r14                ; int64_t arg1
│    │╎╎    0x0000e276      e8c5ebffff     call sym.fullalg_to_move
│    │╎╎    0x0000e27b      4889c5         mov rbp, rax
│    │╎╎    0x0000e27e      4885c0         test rax, rax
│    │╎└──< 0x0000e281      75b5           jne 0xe238
│    │╎     0x0000e283      4c89e1         mov rcx, r12
│    │╎     0x0000e286      488d15f3a301.  lea rdx, str.Failed_to_parse_move_string___s
```

By looking at the disassembly, it can be observed that the return value of `san_to_move` is passed as the first argument of `game_make_move` if it is not 0. Otherwise, the return value of `fullalg_to_move` is passed as input, as long it is not zero either. If both functions `san_to_move` and `fullalg_to_move` return 0 an error message is printed.

By just analyzing the name of the `san_to_move` function, it can be inferred that it takes a move in [SAN](https://en.wikipedia.org/wiki/Chess_notation) notation, and transforms to an internal representation of a `move`. By disassembling the function, it is possible to gain a better understanding of what it does:

```sh
[0x0000e1c0]> s sym.san_to_move

[0x0000d1f0]> pdf
            ; CALL XREF from main @ 0xbb92
            ; CALL XREF from sym.game_make_move_str @ 0xe22b
┌ 96: sym.san_to_move (int64_t arg1, int64_t arg2);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           0x0000d1f0      f30f1efa       endbr64
│           0x0000d1f4      4155           push r13
│           0x0000d1f6      4989fd         mov r13, rdi                ; arg1
│           0x0000d1f9      4889f7         mov rdi, rsi                ; int64_t arg1
│           0x0000d1fc      4154           push r12
│           0x0000d1fe      4989f4         mov r12, rsi                ; arg2
│           0x0000d201      55             push rbp
│           0x0000d202      e889a10100     call sym.san_parse
│           0x0000d207      4885c0         test rax, rax
│       ┌─< 0x0000d20a      7424           je 0xd230
│       │   0x0000d20c      4889c5         mov rbp, rax
│       │   0x0000d20f      4c89ef         mov rdi, r13                ; int64_t arg1
│       │   0x0000d212      4889c6         mov rsi, rax                ; int64_t arg2
│       │   0x0000d215      e826f8ffff     call fcn.0000ca40
│       │   0x0000d21a      4889ef         mov rdi, rbp                ; void *ptr
│       │   0x0000d21d      4989c4         mov r12, rax
│       │   0x0000d220      e86bd9ffff     call sym.imp.free           ; void free(void *ptr)
│       │   ; CODE XREF from sym.san_to_move @ 0xd250
│      ┌──> 0x0000d225      4c89e0         mov rax, r12
│      ╎│   0x0000d228      5d             pop rbp
│      ╎│   0x0000d229      415c           pop r12
│      ╎│   0x0000d22b      415d           pop r13
│      ╎│   0x0000d22d      c3             ret
..
│      ╎│   ; CODE XREF from sym.san_to_move @ 0xd20a
│      ╎└─> 0x0000d230      4c89e1         mov rcx, r12
│      ╎    0x0000d233      488d15ceaf01.  lea rdx, str.Failed_to_parse_SAN_move_string___s ; 0x28208 ; "Failed to parse SAN move string '%s'"
│      ╎    0x0000d23a      be88020000     mov esi, 0x288
│      ╎    0x0000d23f      31c0           xor eax, eax
│      ╎    0x0000d241      488d3da0ae01.  lea rdi, str.build_dreamchess_2gtGVK_dreamchess_0.3.0_dreamchess_src_board.c ; 0x280e8 ; "/build/dreamchess-2gtGVK/dreamchess-0.3.0/dreamchess/src/board.c"
│      ╎    0x0000d248      4531e4         xor r12d, r12d
│      ╎    0x0000d24b      e830050000     call sym.dbg_log
└      └──< 0x0000d250      ebd3           jmp 0xd225
```

The function seems to receive two arguments, possibly of pointer type or int64. This can be further analyzed by setting a breakpoint in gdb and going through the execution.

```
Thread 1 "dreamchess" hit Breakpoint 1, 0x000055852612c1f0 in san_to_move ()
(gdb) x/10x $rsi
0x5585269396f5:    0x33663167    0x00000000    0x00000000    0x00000000
0x558526939705:    0x31000000    0x00000001    0x10000000    0x85268202
0x558526939715:    0x10000055    0x85262020
(gdb) x/s $rsi
0x5585269396f5:    "g1f3"
(gdb) x/10wx $rdi
0x7ffe4bbaad90:    0x00000000    0x00000006    0x00000002    0x00000004
0x7ffe4bbaada0:    0x00000008    0x0000000a    0x00000004    0x00000002
0x7ffe4bbaadb0:    0x00000006    0x00000000
Run till exit from #0  0x000055852612c1f0 in san_to_move ()
0x000055852612ab97 in main ()
(gdb) x $rax
0x0:    Cannot access memory at address 0x0
(gdb) p $rax
$1 = 0
```

It seems that the first argument of the function (`rdi`), is a pointer to the heap that contains some unknown structure. The second argument (`rsi`) is a pointer to the heap, containing a string that represents the move made by the CPU ("g1f3"). Although it is not in SAN notation, it is in coordinate notation. The return value is `0`, maybe denoting failure or an invalid pointer.

In this case, as stated previously the program will continue and call `fullalg_to_move`, which by paying a closer look at the disassembly of `game_make_move_str` is taking the same arguments as `san_to_move`. By setting a breakpoint in this function it is possible to see that this one returns a valid pointer, which is then given to `game_make_move`:

```sh
Thread 1 "dreamchess" hit Breakpoint 2, 0x000055852612be40 in fullalg_to_move ()
(gdb)  x/s $rsi
0x5585269396f5:    "g1f3"
(gdb) x/10x $rdi
0x7ffe4bbaad90:    0x00    0x00    0x00    0x00    0x06    0x00    0x00    0x00
0x7ffe4bbaad98:    0x02    0x00
(gdb) fin
Run till exit from #0  0x000055852612be40 in fullalg_to_move ()
0x000055852612abcd in main ()
(gdb) p $rax
$2 = 94030378063664
(gdb) x/10wx $rax
0x558527485730:    0x00000006    0x00000015    0x0000000c    0x00000000
0x558527485740:    0x00000000    0x00000000    0x00000041    0x00000000
0x558527485750:    0x2746c8b0    0x00005585
```

By knowing this, it is possible to simulate a call to`game_make_move` by first using `fullalg_to_move` to transform a move represented in coordinate notation to a consumable pointer. But before doing this, the first argument of `fullalg_to_move` needs to be understood.

By making an educated guess, to generate a move the state of the board plus the move representation is needed (as you need to translate the coordinates from the coordinate notation to actual board pieces). Since the move representation is already given as the second parameter, probably the first is a pointer to a struct that represents the state of the board.

From the list of externs obtained in the "Static binary analysis" section, there is a function called `get_board`, which might be promising to get such struct.

By disassembling this function in radare2, it can be observed that it receives no arguments and returns a pointer.

```
[0x0000b460]> s sym.get_board
[0x00025a40]> pdf
            ; XREFS: CALL 0x0001da98  CALL 0x0001daa4  CALL 0x0001dab2  CALL 0x0001dac3  CALL 0x0001dad6  CALL 0x0001dc20  
            ; XREFS: CALL 0x0001dc2b  CALL 0x0001dc3a  CALL 0x0001dc4c  CALL 0x0001dc60  CALL 0x0001dec0  CALL 0x0001e00d  
            ; XREFS: CALL 0x0001e0aa  CALL 0x0001e1e1  CALL 0x0001e280  CALL 0x00026796  
┌ 12: sym.get_board ();
│           0x00025a40      f30f1efa       endbr64
│           0x00025a44      488d05751101.  lea rax, [0x00036bc0]
└           0x00025a4b      c3       
```

Knowing all this, it is possible to attempt to move one of the pieces by doing the following:

1. Obtain the board pointer by calling `get_board`.
2. Allocate memory to store the move representation string.
3. Set the move to be issued.
4. Call `fullalg_to_move` to obtain a pointer to the move to be made.
5. Call `game_make_move` to issue the user move.

This was done in gdb to prototype:

```
call (uint64_t*)get_board()
call (uint64_t*)malloc(25)
set {char[5]}$2 = "e2e4"
call (uint64_t*)fullalg_to_move($1, $2)
call (uint64_t*)game_make_move($3)
```

![](https://i.imgur.com/eJS0B9M.png)

The piece was moved by issuing these gdb commands as seen in the image above.

#### Understanding CPU moves

From section "Identifying CPU piece movements" it was stated that each time a piece is moved in the board the function `fcn.0000dc40` is called. By looking at the function call in `main`, additional information such as the arguments passed to the function can be known:

```
│ ││╎││╎╎   0x0000bb92      e859160000     call sym.san_to_move
│ ││╎││╎╎   0x0000bb97      488b7c2408     mov rdi, qword [dest]
│ ││╎││╎╎   0x0000bb9c      4885c0         test rax, rax
│ ││╎││╎╎   0x0000bb9f      4989c7         mov r15, rax
│ ────────< 0x0000bba2      7421           je 0xbbc5
│ ││╎││╎╎   ; CODE XREF from main @ 0xbbd3
│ ────────> 0x0000bba4      31ff           xor edi, edi
│ ││╎││╎╎   0x0000bba6      e8f5730000     call sym.audio_play_sound
│ ││╎││╎╎   0x0000bbab      4c89ff         mov rdi, r15                ; int64_t arg1
│ ││╎││╎╎   0x0000bbae      be01000000     mov esi, 1                  ; int64_t arg2
│ ││╎││╎╎   0x0000bbb3      e888200000     call fcn.0000dc40
│ ││╎││╎╎   0x0000bbb8      4c89ff         mov rdi, r15                ; void *ptr
│ ││╎││╎╎   0x0000bbbb      e8d0efffff     call sym.imp.free           ; void free(void *ptr)
│ ────────< 0x0000bbc0      e90bfdffff     jmp 0xb8d0
│ ││╎││╎╎   ; CODE XREF from main @ 0xbba2
│ ────────> 0x0000bbc5      4c89f6         mov rsi, r14
│ ││╎││╎╎   0x0000bbc8      e873120000     call sym.fullalg_to_move
│ ││╎││╎╎   0x0000bbcd      4989c7         mov r15, rax
│ ││╎││╎╎   0x0000bbd0      4885c0         test rax, rax
│ ────────< 0x0000bbd3      75cf           jne 0xbba4
```

In this case, by looking at the disassembly, it is possible to observe that the return value of `san_to_move` and `fullalg_to_move` is passed to `fcn.0000dc40` as first argument and `1` as the second argument. 

From section "Initiating moves" it was determined that `san_to_move` and `fullalg_to_move` return a pointer representing a move that was translated from either san (standard arithmetic notation) or coordinate notation.

From the exports, it is possible to find the inverse of these functions: `move_to_san` and `move_to_fullalg`. 

`move_to_fullalg` seems to be a better choice to decypher the internal move representation, as chess engines prefer this form of notation. By using radare2 it is possible to extract the arguments to the function:

```
[0x0000b460]> axt sym.move_to_fullalg
sym.move_to_san 0xd1b1 [CALL] call sym.move_to_fullalg
fcn.0000dc40 0xda53 [CALL] call sym.move_to_fullalg
sym.game_make_move 0xe00a [CALL] call sym.move_to_fullalg
[0x0000b460]> s sym.game_make_move
[0x0000dfc0]> pdf
       ╎╎   ; CALL XREF from sym.game_make_move_str @ 0xe23e
       ╎╎   ; CALL XREF from fcn.00024660 @ 0x24840
┌ 115: sym.game_make_move (int64_t arg1);
│      ╎╎   ; arg int64_t arg1 @ rdi
│      ╎╎   0x0000dfc0      f30f1efa       endbr64
│      ╎╎   0x0000dfc4      55             push rbp
│      ╎╎   0x0000dfc5      4889fd         mov rbp, rdi                ; arg1
│      ╎╎   0x0000dfc8      e873fcffff     call fcn.0000dc40
│      ╎╎   0x0000dfcd      85c0           test eax, eax
│     ┌───< 0x0000dfcf      7427           je 0xdff8
│     │╎╎   0x0000dfd1      488b05486602.  mov rax, qword [0x00034620] ; [0x34620:8]=0
│     │╎╎   0x0000dfd8      486315496602.  movsxd rdx, dword [0x00034628] ; [0x34628:4]=0
│     │╎╎   0x0000dfdf      488d3df4d601.  lea rdi, [0x0002b6da]       ; "%s\n"
│     │╎╎   0x0000dfe6      5d             pop rbp
│     │╎╎   0x0000dfe7      488b74d0f8     mov rsi, qword [rax + rdx*8 - 8]
│     │╎╎   0x0000dfec      31c0           xor eax, eax
│     │└──< 0x0000dfee      e9edf2ffff     jmp sym.comm_send
│     │ ╎   ; CODE XREF from sym.game_make_move @ 0xdfcf
│     └───> 0x0000dff8      488b05196602.  mov rax, qword [0x00034618] ; [0x34618:8]=0
│       ╎   0x0000dfff      4889ee         mov rsi, rbp
│       ╎   0x0000e002      488b4010       mov rax, qword [rax + 0x10]
│       ╎   0x0000e006      488b7810       mov rdi, qword [rax + 0x10]
│       ╎   0x0000e00a      e861e7ffff     call sym.move_to_fullalg
```

From this cross reference found in `game_make_move`, it is possible to see that the second parameter passed to `move_to_fullalg` is the first argument given to `game_make_move`, which as seen in the previous section is the internal representation of a move.

Similar to their counterpart, it is probable that `move_to_fullalg` required the state of the board to do a transformation between move representations. This can be verified by instrumenting the call in gdb:

```
(gdb) call (uint64_t*)get_board()
$2 = (uint64_t *) 0x56202b11dbc0
(gdb) call (uint64_t*)move_to_fullalg($2, $rdi)
$3 = (uint64_t *) 0x56202c3e3480
(gdb) x/s 0x56202c3e3480
0x56202c3e3480:    "b1c3"
```

This seems to prove the stated hypothesis.

### Determining initial game state

In order to find out if the CPU player is going to make the first move, i.e; if Dreamchess CPU is playing with the white pieces, it is imperative to find which function is in charge of setting up the configurations selected in the game menu, such as the type of players, difficulty, and level: 

![](https://i.imgur.com/vW4sRA2.png)

To achieve this `frida-trace` was used. `frida-trace` provides different options to make the tracing more granular, to exclude or include specific functions, for example. As explained before, since most videogames use a graphical interface, it is inherent that many functions related to the GUI (Graphical User Interface) such as the renderization and the mouse listeners are constantly called to refresh the game UI, it is better to exclude those calls from the tracing to facilitate the search of the function that provides the configuration of the current game and to include only the `dreamchess` module. In addition to facilitate the search of the target function, frida will perform better when using a more granular specification for the tracing.

```sh
$ frida-trace -I dreamchess -x "gg_*" -x "*draw*" -x "yy*" -x "*gl*"  -x "*mouse*" -x "*screen*" -x "*text_character*" -x "*ui*" dreamchess 
```
![](https://i.imgur.com/nLdEPXs.png)

Even after excluding several functions related to the GUI and user interaction, there are still plenty of functions being traced. To reduce the number of functions to analyze, the tracing was performed twice in two different contexts. The first tracing was performed without initializing the game (before clicking `Start Game`) and the second one was performed while the game was initialized (before, during, and after clicking `Start Game`). Both of the results from the tracing were written into different files and they were compared using `diff` to see what functions are not present before starting the game.

```sh 
#### Before initializing the game 
$ frida-trace -I dreamchess -x "gg_*" -x "*draw*" -x "yy*" -x "*gl*"  -x "*mouse*" -x "*screen*" -x "*text_character*" dreamchess > before_start.txt
$ cat before_start.txt | grep ms | awk {'print $3'} | sort | uniq > before_start_clean.txt
$
#### After initializing the game 
$ frida-trace -I dreamchess -x "gg_*" -x "*draw*" -x "yy*" -x "*gl*"  -x "*mouse*" -x "*screen*" -x "*text_character*" dreamchess > after_start.txt
$ cat after_start.txt | grep ms | awk {'print $3'} | sort | uniq > after_start_clean.txt
$
### Diffing the files
$ diff before_start_clean.txt after_start_clean.txt
```
As a result, a reduced set of functions was obtained. This set of functions could be seen as a snapshot of the functions running at the time of initializing a new game:

```sh 
0a1,2
> |
> audio_play_sound()
2a5,11
> board_setup()
> ch_userdir()
> comm_init()
> comm_poll()
> comm_send()
> config_get_option()
> config_save()
3a13,25
> dbg_log()
> dialog_title_newgame_create()
> find_square()
> fullalg_to_move()
> game_get_engine_error()
> game_get_move_list()
> game_want_move()
> get_backdrop()
> get_black_in_check()
> get_black_in_checkmate()
> get_black_name()
> get_black_piece()
> get_board()
4a27
> get_config()
5a29,41
> get_egg_req()
> get_fading_out()
> get_game_stalemate()
> get_menu_style()
> get_move()
> get_piece_moving_done()
> get_show_egg()
> get_turn_counter()
> get_white_in_check()
> get_white_in_checkmate()
> get_white_name()
> get_white_piece()
> go_3d()
6a43,60
> history_init()
> history_play()
> load_theme()
> make_move()
> move_is_valid()
> move_set_attr()
> move_to_fullalg()
> move_to_san()
> render_scene_3d()
> reset_3d()
> reset_transition()
> resize_window()
> san_to_fan()
> san_to_move()
> set_fade_start()
> set_set_loading()
> start_piece_move()
> text_height()
7a62
> transition_update()
```

Based on the name of the functions, an educated guess to dismiss some of them was made, for instance, the ones related to the function that reproduces a sound when a new game starts or the function that is constantly looking for a checkmate, and so forth. One of the functions that stand out was `dialog_title_newgame_create()` essentially because it contained references to strings that are used in the game's menu just before initializing a game, such as `"Players"`, `"Difficulty"` and `"Level"`. 

```sh 
[0x00024af0]> afl ~dialog_title_newgame_create
0x00020720    1 1260         sym.dialog_title_newgame_create
[0x00024af0]> pdf @ sym.dialog_title_newgame_create~..
...
0x00020742      488d3da79200.  lea rdi, qword str.Players: ; 0x299f0 ; "Players:"
   0x00020749      4889c3         mov rbx, rax
   0x0002074c      e8cf84ffff     call sym.gg_label_create
   0x00020751      31ff           xor edi, edi
   0x00020753      4989c4         mov r12, rax
   0x00020756      e8d5a6ffff     call sym.gg_vbox_create
   0x0002075b      4889c5         mov rbp, rax
   0x0002075e      e8dd55ffff     call sym.gg_container_get_class_id
   0x00020763      4c8d05f28100.  lea r8, qword str.gg_container_t ; 0x2895c ; "gg_container_t"
   0x0002076a      b988000000     mov ecx, 0x88
   0x0002076f      4889ef         mov rdi, rbp
   0x00020772      488d15179300.  lea rdx, qword str.build_dreamchess_w2udAl_dreamchess_0.3.0_dreamchess_src
   0x00020779      89c6           mov esi, eax
   0x0002077b      e85094ffff     call sym.gg_check_cast
   0x00020780      4c89e6         mov rsi, r12
   0x00020783      4889c7         mov rdi, rax
   0x00020786      e8e556ffff     call sym.gg_container_append
   0x0002078b      488d3d679200.  lea rdi, qword str.Difficulty: ; 0x299f9 ; "Difficulty:"
   0x00020792      e88984ffff     call sym.gg_label_create
   0x00020797      4989c4         mov r12, rax
   0x0002079a      e8a155ffff     call sym.gg_container_get_class_id
   0x0002079f      4c8d05b68100.  lea r8, qword str.gg_container_t ; 0x2895c ; "gg_container_t"
   0x000207a6      b98b000000     mov ecx, 0x8b
   0x000207ab      4889ef         mov rdi, rbp
   0x000207ae      488d15db9200.  lea rdx, qword str.build_dreamchess_w2udAl_dreamchess_0.3.0_dreamchess_src
   0x000207b5      89c6           mov esi, eax
   0x000207b7      e81494ffff     call sym.gg_check_cast
   0x000207bc      4c89e6         mov rsi, r12
   0x000207bf      4889c7         mov rdi, rax
   0x000207c2      e8a956ffff     call sym.gg_container_append
   0x000207c7      488d3d379200.  lea rdi, qword str.Level:   ; 0x29a05 ; "Level:"
   0x000207ce      e84d84ffff     call sym.gg_label
```


After that function is executed, some functions related to seting up the configuration of the game are executed:

```sh 
2206 ms  dialog_title_newgame_create()
  2206 ms     | set_pgn_slot()
  2206 ms     | config_get_option()
  2206 ms     |    | option_group_find_option()
  2206 ms     | config_get_option()
  2206 ms     |    | option_group_find_option()
  2206 ms     | config_get_option()
  2206 ms     |    | option_group_find_option()
  2207 ms     | get_menu_style()
  2207 ms  audio_poll()
  2207 ms  get_credits()
  ...
  4320 ms  get_col()
  4321 ms  get_col()
  4321 ms  audio_poll()
  4321 ms  convert_event()
  4321 ms  set_set_loading()
  4321 ms  config_get_option()
  4321 ms     | option_group_find_option()
  4321 ms  config_get_option()
  4321 ms     | option_group_find_option()
  4321 ms  config_get_option()
  4321 ms     | option_group_find_option()
  4321 ms  dbg_log()
  4322 ms  get_egg_req()
  4322 ms  get_config()
  4322 ms  get_config()
  4322 ms  get_config()
  4322 ms  get_config()
  4322 ms  config_save()
  4322 ms     | option_group_save_xml()
  4322 ms     |    | ch_userdir()
  4322 ms  audio_poll()

```

After those functions are executed, the game starts rendering and setting up the parameters set in the dialog menu using the functions `config_get_option()` and `get_config`. The function `get_config` is self-explanatory, it just reads from an object called `config`.

```sh
[0x0000b3f0]> s sym.get_config
[0x00024af0]> pdf
            ; XREFS: CALL 0x00020530  CALL 0x0002053c  CALL 0x0002058b  CALL 0x00020596  CALL 0x000205a8  
            ; XREFS: CALL 0x000205b3  CALL 0x000205c8  CALL 0x000205d3  CALL 0x00025761  CALL 0x000257a2  
            ; XREFS: CALL 0x000257e4  CALL 0x00025802  
┌ 8: sym.get_config ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
│           0x00024af0      488d05993501.  lea rax, qword obj.config   ; 0x38090
└           0x00024af7      c3             ret
[0x00024af0]> 

```

By attaching a gdb session to the running process (`gdb -p <PID>`), setting up a breakpoint in the function `get_config` (`(gdb) b get_config`) and then continuing the program until the function is called, it is possible to analyze the contents of the object:

> The function `get_config` is called several times before starting the game, but the important one is the last call since, at that moment, the object contains all the configuration parameters, so the hexdump show below was made after the last time `get_config`


For the configuration `Players: Human vs CPU, Difficulty: Normal, Level: 1`

```sh
0x55b609af1090 <config>:    0x00000000    0x00000001    0x00000000    0x00000001
```
For the configuration `Players: CPU vs Human, Difficulty: Normal, Level: 3`

```sh
0x55b609af1090 <config>:    0x00000001    0x00000000    0x00000000    0x00000003
```
For the configuration `Players: Human vs Human, Difficulty: Normal, Level: 5`

```sh
0x55b609af1090 <config>:    0x00000000    0x00000000    0x00000000    0x00000005
```

The first two 4-byte words change depending on the *Players* setting. If the first 4-byte word is `0x0` and the second 4-byte word is `0x1`, it means that the `Human` is going to play with the white pieces. Likewise,  If the first 4-byte word is `0x1` and the second 4-byte word is `0x0`, it means that the `Human` is going to play with the black pieces. By understanding, the goal to know if the Dreamchess CPU is playing with the white pieces or with the black pieces, has been accomplished. This is going to be very useful when instrumenting the game later.

## Interacting with chess engines

Most of the chess engines implement [UCI](https://www.chessprogramming.org/UCI) (Universal Chess Interface). And some engines expose a UCI command-line interface, such as the case of StockFish. Through UCI you can request a chess engine to calculate the best possible moves based on the state of the board.

There are two different ways to represent the state of a board in a UCI compliant chess engine. Either through [FEN](https://en.wikipedia.org/wiki/Forsyth%E2%80%93Edwards_Notation) (Forsyth–Edwards Notation) or a list of coordinate notated moves.

In this case, as the functions that were found can translate internal representations into coordinate notated moves, the second approach will be done. 

To exemplify this, a simple set of commands will be sent to StockFish to request for the next move:

```
uci  
position startpos moves e2e4 d7d6
go ponder
stop
```
In this case, with the `uci` command the engine is started. With `position startpos e2e4 d7d6`, it is indicated that the position to be evaluated is from a start position move the piece in `e2` to `e4`, then move `d7` to `d6`. Then `go ponder` indicated the engine to analyze the current position and `stop` to finish calculating and return an answer.

```
$ stockfish
Stockfish 11 64 by T. Romstad, M. Costalba, J. Kiiski, G. Linscott
uci
id name Stockfish 11 64
id author T. Romstad, M. Costalba, J. Kiiski, G. Linscott

option name Debug Log File type string default 
option name Contempt type spin default 24 min -100 max 100
option name Analysis Contempt type combo default Both var Off var White var Black var Both
option name Threads type spin default 1 min 1 max 512
option name Hash type spin default 16 min 1 max 131072
option name Clear Hash type button
option name Ponder type check default false
option name MultiPV type spin default 1 min 1 max 500
option name Skill Level type spin default 20 min 0 max 20
option name Move Overhead type spin default 30 min 0 max 5000
option name Minimum Thinking Time type spin default 20 min 0 max 5000
option name Slow Mover type spin default 84 min 10 max 1000
option name nodestime type spin default 0 min 0 max 10000
option name UCI_Chess960 type check default false
option name UCI_AnalyseMode type check default false
option name UCI_LimitStrength type check default false
option name UCI_Elo type spin default 1350 min 1350 max 2850
option name SyzygyPath type string default <empty>
option name SyzygyProbeDepth type spin default 1 min 1 max 100
option name Syzygy50MoveRule type check default true
option name SyzygyProbeLimit type spin default 7 min 0 max 7
uciok
position startpos moves e2e4 d7d6
go ponder
...
stop
bestmove d2d4 ponder g8f6
```

There are many wrappers for integrating StockFish into diverse programming languages. As Frida is usually run through Python scripts, PyPI StockFish was used.

The previous example can be done in a python script as follows:

```
$ python3
Python 3.8.2 (default, Apr 27 2020, 15:53:34) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
>>> from stockfish import Stockfish
>>> 
>>> stockfish = Stockfish("/usr/games/stockfish")
>>> stockfish.set_position(['e2e4', 'd7d6'])
>>> print(stockfish.get_best_move_time(1000))
d2d4

```

## Instrumenting with Frida  

Frida is a dynamic code instrumentation toolkit that lets you inject snippets of JavaScript into binaries. It allows debugging with full access to memory, it is able to intercept function calls and execute native functions inside the process. Frida injects the javascript engine [duktape](https://duktape.org/) to accomplish those tasks. More details about Frida's API can be found on its official [website](https://frida.re/docs/javascript-api/) 

The next JS was used to make possible the instrumentation of Dreamchess and make it play against a crafted agent, which uses Stockfish to determine the best moves to play.

```js
var next_move = "" // Used to store the asynchronous value returned by the python script
var ptr_mem_fullalg = Memory.alloc(32) // Allocate memory to store the string representation given by the Python script
var reset = 0; // Used to know if a new game has started

// Pointers to the functions that are going to be used
var ptr_move = Process.getModuleByName("dreamchess").base.add(0xdc40); // Function to intercept the movement of a piece
var ptr_game_make_move = Module.findExportByName(null, "game_make_move"); // This function is used by Dreamchess to recieve movements from the user, in this case, the movements are going to be passed from StockFish
var ptr_get_board = Module.findExportByName(null, "get_board"); // It returns the current board.
var ptr_fullalg_to_move = Module.findExportByName(null, "fullalg_to_move"); // Transforms strings in the notation used by StockFish (coordinate notation) into a dreamchess struct 
var ptr_move_to_fullalg = Module.findExportByName(null, "move_to_fullalg"); //T he move made by dreamchess is converted into an coordinate notation to be processed by StockFish (or other engines)
var ptr_history_init = Module.findExportByName(null, "history_init");// It is called every time a new game is initialized
var ptr_get_config = Module.findExportByName(null, "get_config"); // It returns the configuration of the current game
var ptr_game_want_move = Module.findExportByName(null, "game_want_move");// The function is called when the board has been set up and it is ready be played. It is only going to be used when "Human" player is playing with the White pieces

// NativeFunction wrapper of the functions previously defined as function pointers
var fn_game_make_move = new NativeFunction(ptr_game_make_move, 'pointer', ['pointer', 'pointer']); 
var fn_get_board = new NativeFunction(ptr_get_board, 'pointer', []); 
var fn_fullalg_to_move = new NativeFunction(ptr_fullalg_to_move, 'pointer', ['pointer', 'pointer']);
var fn_move_to_fullalg = new NativeFunction(ptr_move_to_fullalg, 'pointer', ['pointer', 'pointer']);
var fn_get_config = new NativeFunction(ptr_get_config, 'pointer', []);

// Intercept history_init to notify the engine that it needs to reset the board, and to indicate a new game has started
Interceptor.attach(ptr_history_init,
{
    onLeave: function (retval) 
    {   
        send("reset");
        reset = 1; // Set the reset flag, as this is a new game
    }
});

// Intercept the first call to game_want_move. Check if user is playing as whites and issue the first move
Interceptor.attach(ptr_game_want_move,
{
    onLeave: function (retval) 
    {   
        // Game is set up
        if (reset)
        {
            
            var config = fn_get_config();//The function that reads the object config
            var whiteCPU = config.readUInt() //Read the first 4 bytes, if it contains a 0x1, then CPU is playing with White pieces
            var blackCPU = config.add(4).readUInt() //Read the next 4 bytes, if it contains a 0x1, then CPU is playing with Black pieces
            console.log("Started game! CPU Whites? " + whiteCPU); //If CPU is playing with white pieces, prints 1 otherwise prints 0

            // If CPU is playing with Blacks, Human starts
            if (blackCPU)
            {
                send(""); // Send an empty move to make StockFish return a move 
                recv(get_move).wait(); //wait until receive a move from stockfish
                
                var board = fn_get_board(); // Since StockFish, playing as Human in this scneario, the board is needed.  
                ptr_mem_fullalg.writeUtf8String(next_move); // The move is written into the memory allocated previously
                var ptr_next_move = fn_fullalg_to_move(board, ptr_mem_fullalg); // fn_fullalg_to_move transforms from coordinate notation into a struct used by Dreamchess
                console.log(ptr_next_move); // Prints the move that is going to be made
                fn_game_make_move(ptr_next_move, board); // Actually makes the move
            }
            // Catch the error in case the game mode was set as Human vs Human
            else if (!whiteCPU && !blackCPU)
            {
                console.log("Human vs Human? ... Nothing to do here");
            }
            reset = 0; // To avoid this function is called again unless a new game starts
        }
    }
});

// Intercept calls when a piece is moved. Since 'user' moves are instrumented by Frida, only CPU calls are intercepted.
Interceptor.attach(ptr_move, 
{
    onEnter: function (args) 
    {
        var board = fn_get_board();
        var ptr_move = fn_move_to_fullalg(board, args[0]); // Transforms from Dreamches notation into coordinate notation
        var current_move = ptr_move.readUtf8String(); // Reads the movement from Dreamchess that has already been transformed into coordinate notation that later is going to be send to StockFish
        send(current_move); // Send the move to StockFish
        this.recv_wait = recv(get_move); // Store the recv object to avoid busy waiting state
    },
    onLeave: function (retval) 
    {
        var board = fn_get_board(); //The board information needs to be requested again since the state of the board has changed since a move has just been made
        this.recv_wait.wait(); //Wait until StockFish responds with a move

        ptr_mem_fullalg.writeUtf8String(next_move); //Write the move given by StockFish into the buffer 
        var ptr_next_move = fn_fullalg_to_move(board, ptr_mem_fullalg); //fn_fullalg_to_move transforms from coordinate notation into a struct for Dreamchess
        fn_game_make_move(ptr_next_move, board); // Makes the move
    }
});

// Callback when python provides a move to be made
function get_move(m)
{
    next_move =  m //The movement is saved
}
```

Frida also implements a Python API to perform bindings. Since there is a straight forward Stockfish API in Python, as mentioned in the previous section, a python agent was created to load the JS script into the dreamchess process and handle transactions to the external chess engine. 

```py 
# Imports the libraries, frida and stockfish for Python
import frida
import sys
from stockfish import Stockfish
# Path to engine
stockfish = Stockfish("/usr/games/stockfish")
# Define a list to store the moves from the current game
moves = []

# Read the agent source
with open("chess.js", "r") as f:agent = f.read()
# Create a session frida 
session = frida.attach("dreamchess")
# Create a script and loads it into frida
script = session.create_script(agent)
script.load()

# Receives a function from the JS script
def incoming(message, data):
    print(message['payload'])
    # If it is performing a reset, it will clean the "moves" list
    if message['payload'] == "reset": 
        moves.clear()
    # Otherwise, it is sending a move
    else:
        # Appends the new move to the list
        moves.append(message['payload'])
        # All the moves made so far are going to be sent to StockFish
        stockfish.set_position(moves)
        # Analyzes the move that was played by the oponent during 1 second and returns the best move according to StockFish
        move = stockfish.get_best_move_time(1000)
        # Appends the issued move to the list
        moves.append(move)
        print(move)
        # Sends the move to the JS agent injected in the process
        script.post(move)
        
# Every time Frida sends a message, it shall call the "incoming" function
script.on("message", incoming)

# Block so that the program does not quit.
sys.stdin.read()
```
## Result

![](https://i.imgur.com/buDaQ9F.gif)


**Happy hacking :)**
