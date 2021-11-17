---
title: "HKCERT CTF 2021: 回到十二歲 Scratch Tic-Tac-Toe"
description: ""
date: 2021-11-16T02:00:32+08:00
lastmod: 2021-11-16T02:00:32+08:00
math: false
draft: false
tags: ["ctf", "hkcert21", "scratch"]
---

> **This post is part of the [HKCERT 2021 CTF series](/tags/hkcert21).**

> **This writeup is written by one of my teammates.**

---

|     Name     | 回到十二歲 (Scratch Tic-Tac-Toe) |
| :----------: | -------------------------------- |
|     Tags     | misc                             |
|    Points    | 200                              |
|  Difficulty  | ★★☆☆☆                            |
|    Solves    | 86 (total of all four divisions) |
| Release Date | 2021-11-13 06:00:00              |

> If you can beat me in the game I'll give you the flag!
>
> https://scratch.mit.edu/projects/596813541/

---

First, we need to win the bot.

{{< figure src="1.png" width=400 >}}

Then, choose title and there was a yellow note. After dragging down the note, we can see some code underneath.

{{< figure src="2.png" width=400 >}}

One of the blocks has `result = 03vx{_ihq0xhh7svtx}t{sv180x{r`. Inserting this as the answer, we noticed the variable result on the left bar became `gjbdqs109gd00n}b_dr_q}bhogdq{` which is not the same as the result in the code.

Then inserting `hkcert21{` as the answer and found out the variable result became `03vx{_ihq`. After some matching and guessing work, we were able to get the flag `hkcert21{he11o_caesar_cipher}`.
