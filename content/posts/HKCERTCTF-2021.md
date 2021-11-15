---
title: "HKCERTCTF 2021 Writeup"
date: 2021-11-15T17:00:10+08:00
draft: false
categories:
 - ctf
tags:
 - ctf
 - writeup
 - web
 - misc
 - pwn
 - reverse
 - crypto
summary: "Writeup for HKCERT CTF 2021"
---

# Background
12 Nov 2021, 18:00 HKT — 14 Nov 2021, 18:00 HKT  
Format: Jeopardy  
Official URL: https://ctf.hkcert.org/  
Organisers: HKCERT and HKPC  
Co-organisers: AiTLE, BlackB6a, eLC, ISOCHK, PISA, VXRL  
CTFtime: https://ctftime.org/event/1432  
I played this HK local CTF last week with my friends and end up with the 5-th in the open category. I learnt a lot but also realised that I really need to improve more of my skills, especially in crypto. (I really want to solve the crypto challs next year)  
This is a well-organized CTF with good theme and platform plus the HK songs, and all of the high quality challenges, big thanks to BlackB6a! I am going to share some of the challenges that I was able to / almost solve (also as the requirement for the top 5 teams to complete some selected writeup).

# Challenges
## Freedom (Cipher Mode Picker) - Crypto (100 points)
### Challenge :
>> Freedom where's our freedom? Freedom what would it be Can you tell me what's the reason? Reason that meant to be

> Every slightest mistake in cryptography would lead to a disastrous result. Let's see what will happen when you allow end-users to pick the mode of operation... 
> nc chalp.hkcert21.pwnable.hk 28102

### Files : 
[freedom_ff0173b179d746386dca0e93e6c00d47.zip](/files/HKCERT/freedom_ff0173b179d746386dca0e93e6c00d47.zip)

### Solution : 
From the provided `chall.py`, we can observe: 

1. The length of flag is `80`.
2. A fix `key` and `IV` are used for each connection
3. There are 5 mode of operations implemented ('ECB', 'CBC', 'CFB', 'OFB' and 'CTR') and you can either provide data to the server for the encryption or let the server encrypting the flag, for at most 5 times per connection. But you can only use 1 mode per connection.

If you are familiar with these operation, you may spot that the weakness is the reuse of IV... Let's have a look into the mode 'CFB' and 'OFB': 

![1920px-CFB_encryption svg](https://user-images.githubusercontent.com/19466939/141827418-59c34dbf-5393-4ba1-9846-5454bed8d7fb.png)
![1920px-OFB_encryption svg](https://user-images.githubusercontent.com/19466939/141827405-17ae2f4d-2cdc-46db-a20e-2a8bc32a204f.png)

As we can see, the encryption procedure of CFB and OFB are actually the same. Therefore if we first provide all zero as the data to encrypt with one mode (e.g., CFB), it will return the encryption of each block itself. Then we request for the encrypted flag with another mode (e.g., OFB) and xor them together, we will get the flag! 

For CFB:
```
C_{0} = IV
C_{i} = E_{k}(C_{i-1}) xor P_{i}
P = 0 => C_{i} = E_{k}(C_{i-1})
```
For OFB:
```
O_{0} = IV
O_{i} = E_{k}(O_{i-1})
C_{i} = E_{k}(O_{i-1}) xor P_{i}
```
```
E_{k}(C_{i-1}) xor E_{k}(O_{i-1}) xor P_{i} = P_{i} (which is the flag)
```
**Solve:**
```
from pwn import *
from Crypto.Util.number import long_to_bytes

def xor(s1, s2):
    return ''.join([str(int(a) ^ int(b)) for a,b in zip(s1,s2)])

r = remote("chalp.hkcert21.pwnable.hk", 28102)
r.recvuntil(b'> ')
r.sendline(b'cfb data '+ b'0'*160)
s1 = r.recvline()[:-1]
r.recvuntil(b'> ')
r.sendline(b'ofb flag')
s2 = r.recvline()[:-1]
r.close()
t = xor(bin(int(s1,16))[2:],bin(int(s2,16))[2:])
print(long_to_bytes(int(t,2)))
```

FLAG : **hkcert21{w3_sh0u1d_n0t_g1v3_much_fr3ed0m_t0_us3r5_wh3n_1t_c0m3s_t0_cryp70gr4phy}**

## 所有遺失的東西 (All Missing) - pwn (150 points)
### Challenge :
> You lose all the things, including the chance of getting out of the jail of python.
> nc chalp.hkcert21.pwnable.hk 28004

### Files : 
[pyjail1_f7be93352498ebd158a0a9fc069b30e9.zip](/files/HKCERT/pyjail1_f7be93352498ebd158a0a9fc069b30e9.zip)

### Solution : 
I was working on some other challenge while my teammate asked for help, so I checked this challenge. It is a Pythohn jail escape challenge. `__builtins__` is clear and the square brackets`[]` are not allowed to use. 

I did some googling and found some payloads such as `().__class__.__base__.__subclasses__()` or `''.__class__.__mro__.__getitem__(1).__subclasses__()` to get some "benign" subclasses from modules imported in memory by default, even we dont have `__builtins__`.Moreover, we can use `__getitem__(i)` or `pop(i)` to replace the use of `[]`.

After some checking, we found the class `<class 'os._wrap_close'>` which has the method `popen`. We first call `__init__` to initiate with `__globals__` to get the method as dictionary.

**Solve:**

```
().__class__.__base__.__subclasses__().pop(133).__init__.__globals__.pop('system')('cat flag.txt')
```
FLAG : **hkcert21{nev3r_uSe_pYth0n_45_sanDBox}**

## 留下來的人 (The Remaining One) - pwn, misc (300 points)
### Challenge :
> Find out the only one who always stand by you, that's the key of the escape.
> nc chalp.hkcert21.pwnable.hk 28005

### Files : 
[pyjail2_5ce6175d2c2cc1469d1188f029c356cb.zip](/files/HKCERT/pyjail2_5ce6175d2c2cc1469d1188f029c356cb.zip)

### Solution : 
It was at the midnight after finished the first Python jailbreak chall above. I decided to have a look into the second part as well and got the first blood luckily.

The difference between this and the last chall is that the payload was restricted within length `59`. Therefore we cannot "reuse" the payload in the first part. However, is it really the case?

Actually the another diff alerted me, unlike the first part that you can only have 1 input, you can have infinite round of input. This made me thinking about "splitting and storing" the payload in each round and call it at the end. First I tried something like `a = "xxx"` but it returned a SyntaxError, as it is inside the `eval` you cannot assign variable like that.

Then I realised that although `__builtins__` was clear, this dict still exist and can be used. To assign the value for dictionary, we can use `update`. Therefore, what we need to do is just split the previous payload, use `update` to store the payload to the dict and ...Done!

**Solve:**

```
__builtins__.update({'a': ().__class__.__base__})
__builtins__.update({'a': a.__subclasses__()})
__builtins__.update({'a': a.pop(133).__init__})
__builtins__.update({'a': a.__globals__})
a.pop('system')('cat flag.txt')
```
FLAG : **hkcert21{cr0sS_namesP4se__builtin__breaK_the_JAIL}**

## 最難行的路 (The Hardest Path) - reverse, misc (300 points)
### Challenge :
>> 寧願不揀最易的路 行極還未到 寧願你最後未傾慕 但信念安好 在意的 不再是 愛的煩惱 是哪樣做人 更清高 餘生那段旅途 與哪類人共舞

> When you think reverse engineering is hard, try working on reverse engineering challenges those need your algorithmic thinking skills!

> nc chalp.hkcert21.pwnable.hk 28005

### Files : 
[the-hardest-path_e00c6aa7b64b8dc2a06e577937b5b07c.zip](/files/HKCERT/the-hardest-path_e00c6aa7b64b8dc2a06e577937b5b07c.zip)

### Solution : 
This is my favourite challenge in this CTF since I made a huge mistake when solving it...
Two python files were provided, `chall.py` and `lost.py`. The `chall.py` serves as a server, receving a Proof-of-Work and some "inputs". If the input is correct, the flag will be returned. `lost.py` contains the real chall and logic, with some slightly obfuscated codes/variables.

To put it simply, after the reverse,

* Line 3 defined 4 instructions of movements, i.e., North ('N'), East ('E'), West ('W') and South ('S').
```
mystery = 'NEWS'
```
* Line 5 defined a function to represent a dead-end.
```
def _29aa7a86665899ed(_050ca071ab51aece): raise Exception('😵‍💫💫🧱')
```
* Line 7 - 15 defined the checking on whether the instructions is one of the "NEWS", as well as whether we have arrived the end after all provided instructions
```
def _f42fb5e137443877(_a78810bb76cc7d70, *_ab1bbf35017f4f42):
    def _e6aea2db2242b19f(_41d28eb8c27952c3):
        if len(_41d28eb8c27952c3) == 0:
            if not _a78810bb76cc7d70: raise Exception('🤷🏁😕')
            return
        _03d38fa3a589db14, _41d28eb8c27952c3 = _41d28eb8c27952c3[0], _41d28eb8c27952c3[1:]
        return globals()[_ab1bbf35017f4f42[mystery.index(_03d38fa3a589db14)]](_41d28eb8c27952c3) if _03d38fa3a589db14 in mystery else _e6aea2db2242b19f(_41d28eb8c27952c3)

    return _e6aea2db2242b19f
```
* The remaining lines are the paths / relationship of each node, telling you the neighbour of each direction you go from this node (_f42fb5e137443877[0] => whether it is the end,_f42fb5e137443877[1], _f42fb5e137443877[2], _f42fb5e137443877[3], _f42fb5e137443877[4] -> 'N', 'E', 'W', 'S')
```
...<snipped>...
_2f00e51306a05b87 = _29aa7a86665899ed (represent dead-end)
_328518a497015157 = _f42fb5e137443877(False, "_ef5d07da6a407ff3", "_3f49b6a9053121fb", "_60de30732830eab8", "_3ff69bef8add0e90") (The starting point)
_8b0eb6f195ae182a = _f42fb5e137443877(True, "_92ccf583b1b065ea", "_d3084505a4a12123", "_e335a503c47e5243", "_ebff1548ca6e8dbd") (The only "True", meaning it is the end)
...<snipped>...
```

Therefore it is actually a chall that finding a path from the starting point `_328518a497015157` to the end `_8b0eb6f195ae182a`, with the movement as the instructions (a list of "NNNNEEEEWWWWSSSS").

First I copied the lines after line 15 to another file `path.txt` for parsing. As we dont want to move into a dead-end, I simply ignored all of them (i.e. the node = `_29aa7a86665899ed`), otherwise, I stored it with the neighbour into a dictionary. Then I walk through the dict again to find out all the dead-end node.
```
dict = {}
f = open("path.txt", "r")
lines = f.read()
for line in lines.split('\n'):
    if line:
        tmp = line.split('=')
        if tmp[1] == ' _29aa7a86665899ed':
            continue
        else:
            t = tmp[1].split('"')
            if "False" in tmp[1]:
                dict[tmp[0][:-1]] = [0, t[1], t[3], t[5], t[7]]
            else:
                dict[tmp[0][:-1]] = [1, t[1], t[3], t[5], t[7]]
for k, v in dict.items():
    dict[k] = [0 if (not(x in dict) and not(x)) else x for x in v]
```
Next we need to walk and get a path from the starting point to the end. I implemented a DFS (Depth-first search) to get the path
```
def dfs(node):
    if 1 in dict[node]:
        return 1
    if node not in visited:
        visited.add(node)
        for i, neighbour in enumerate(dict[node]):
            if neighbour != 0:
                if dfs(neighbour):
                    path.append([neighbour, mystery[dict[node].index(neighbour)-1]])
                    return 1
    else:
        return 0
```
Then I got an error below
```
RecursionError: maximum recursion depth exceeded
```
and I did the biggest mistake in my life, that is adding `sys.setrecursionlimit(2000)` to my code to extend the limit of recursion depth, so that my program can work... and it did output the solution
```
SSSSEENNEESSSSEENNEEEEEEEESSSSEESSSSEESSEENNEESSSSWWSSWWSSSSWWSSSSWWWWWWSSWWSS...<snipped>...EEEEENNEEEESSEENNEEEESSSSSSSSWWSSWWSSSSWWSSSSSSEESSSSEEEESSEENNEESSEEEE
```
and then I got a `no good!` instead of the flag from the server. What could be wrong? (Someone: everything can go wrong will go wrong) After some dry run I am pretty sure that it is a valid path and it was around 3/4 at midnight so I decided let my brain to have some rest. On the next day I tried to change the code in `chall.py` to not catch the error and I got the same error again:
```
RecursionError: maximum recursion depth exceeded
```
Then I realised the problem is my solution is not optimized, i.e. we need to find the shortest path. Therefore, BFS (Breadth-First Search) should be used. (There is no weight/same weight for each edge in this chall)
```
def bfs(start, goal):
    visited = []
    queue = [[[start, '-1']]]
    while queue:
        path = queue.pop(0)
        node = path[-1][0]
        if node not in visited:
            neighbours = dict[node]
            for i, neighbour in enumerate(neighbours):
                if neighbour != 0 and neighbour in dict:
                    new_path = list(path)
                    new_path.append([neighbour, mystery[i-1]])
                    queue.append(new_path)
                    if neighbour == goal:
                        return new_path
            visited.append(node)
    return 0
```
and...we got the shorter path!
```
SSSSEENNEESSSSEENNEEEEEEEESSSSEESSSSWWSSSSEESSEESSSSWWSSSSWWWWWWSSWWSSSSSSEEEES...<snipped>...SSWWESSEENNEEEESSSSSSSSWWSSWWSSSSWWSSSSSSEESSSSEEEESSEENNEESSEEEE
```

**Solve:**

`process.py`
```
flag = ""
mystery = 'NEWS'
dict = {}

f = open("path.txt", "r")
lines = f.read()
for line in lines.split('\n'):
    if line:
        tmp = line.split('=')
        if tmp[1] == ' _29aa7a86665899ed':
            continue
        else:
            t = tmp[1].split('"')
            if "False" in tmp[1]:
                dict[tmp[0][:-1]] = [0, t[1], t[3], t[5], t[7]]
            else:
                dict[tmp[0][:-1]] = [1, t[1], t[3], t[5], t[7]]
      
for k, v in dict.items():
    dict[k] = [0 if (not(x in dict) and not(x)) else x for x in v]

def bfs(start, goal):
    visited = []
    queue = [[[start, '-1']]]
    while queue:
        path = queue.pop(0)
        node = path[-1][0]
        if node not in visited:
            neighbours = dict[node]
            for i, neighbour in enumerate(neighbours):
                if neighbour != 0 and neighbour in dict:
                    new_path = list(path)
                    new_path.append([neighbour, mystery[i-1]])
                    queue.append(new_path)
                    if neighbour == goal:
                        return new_path
            visited.append(node)
    return 0
p = bfs('_328518a497015157', '_8b0eb6f195ae182a')

for x in p:
    flag = flag + x[1]
print(flag[1:])
```
`solve.py`
```
from pwn import *
import os
import base64
import hashlib
ans = "SSSSEENNE...<snipped>...ENNEESSEEEE"

r = remote("chalp.hkcert21.pwnable.hk", 28117)
r.recvuntil('🔧')
challenge = base64.b64decode(r.recvline()[:-1])
while True:
    response = os.urandom(8)
    h = hashlib.sha256(challenge + response).digest()
    if h.startswith(b'\x00\x00\x00'):
        r.recvuntil('🔩')
        r.sendline(base64.b64encode(response))
        break
print(r.recvuntil('🥺 '))
r.sendline(ans)
r.interactive()
```
FLAG : **hkcert21{4lw4ys_l0ok_4t_s74ck_0verf1ow_wh3n_y0u_w4nt_t0_4v01d_s7ack_0v3rfl0ws}**

P.S. I sent this meme to the author after solved this challenge :)
![haha](https://user-images.githubusercontent.com/19466939/141827583-69430cb6-5f2e-425d-8699-74d7f9c892a4.png)

...To be updated...
