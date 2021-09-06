---
layout: post
title: "FwordCTF 2021 Writeup"
date: 2021-08-31T23:00:00
draft: false
categories:
 - ctf
tags:
 - ctf
 - writeup
 - crypto
summary: "Writeup for FwordCTF 2021"
---

# Background
28 Aug 2021, 01:00 HKT — 29 Aug 2021, 13:00 HKT  
Format: Jeopardy  
Official URL: https://ctf.fword.tech/  
Event organizers: Fword  
CTFtime: https://ctftime.org/event/1405  
This is the first CTF I participated after I decided to join back the CTF world. Only 2 simple crypto were solved, showing that there is plenty of rooooooooooooooooooom for improvement of my CTF skills.  

# Challenges
## Leaky Blinders - Crypto (100 points)
### Challenge :
> Get the flag, by order of the leaky fookin blinders..  
> `nc 52.149.135.130 4869`

### Files :  
[leaky_blinders.py](https://github.com/MehdiBHA/FwordCTF-2021/blob/main/Leaky%20Blinders/leaky_blinders.py)

### Solution : 
From the `decrypt` function below, we know that the provided ciphertext will xor with the provided key then perform the standard AES decryption.

```
def decrypt(cipher, k):
    aes = AES.new(k, AES.MODE_ECB)
    cipher = xor(cipher, k)
    msg = unpad(aes.decrypt(cipher), 16)
    return msg
```
The goal is to provide a ciphertext and key that output **"FwordCTF"** after the decryption. It is obvious that one can encrypt the word offline and provide the used ciphertext and key to obtain the flag.  

**Solve:**
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys, os, pwc

FLAG = b"FwordCTF{###############################################################}"
key = os.urandom(32)

def encrypt(msg):
    aes = AES.new(key, AES.MODE_ECB)
    if len(msg) % 16 != 0:
        msg = pad(msg, 16)
    cipher = aes.encrypt(msg)
    cipher = xor(cipher, key)
    return cipher

io = pwn.remote("52.149.135.130", 4869)
io.recvuntil(b'> ')
io.sendline('2')
io.sendline(key.hex())
io.sendline(encrypt(FLAG).hex())
io.interactive()
```
FLAG : **FwordCTF{N3v3r_x0r_w1thout_r4nd0m1s1ng_th3_k3y_0r_m4yb3_s3cur3_y0ur_c0d3}**

Official writeup : [The Real Crypto Solution](https://github.com/MehdiBHA/FwordCTF-2021/tree/main/Leaky%20Blinders)

## Boombastic - Crypto (738 points)
### Challenge :
> A pen and a paper, thats's all you need to watch the movie.  
> `nc 52.149.135.130 4872` 

### Files :  
[boombastic.py](https://github.com/MehdiBHA/FwordCTF-2021/blob/main/Boombastic/boombastic.py)


### Solution : 
By doing some maths we can recover the value of `secret` from knowing `s`, `r` and `p`, as shown below (x is secret):  
![equation1](https://user-images.githubusercontent.com/19466939/131537192-9a076340-813e-4200-9d46-4de54dede1d7.png)  
![equation2](https://user-images.githubusercontent.com/19466939/131537206-2ae07e20-d713-4fa0-a9cc-89ac7ce735e1.png)  
![equation3](https://user-images.githubusercontent.com/19466939/131537210-8bec7101-c64a-4a27-b59e-c38c9b415801.png)  
![equation4](https://user-images.githubusercontent.com/19466939/131537216-7f313e67-3c60-4799-af4d-7682121ebe42.png)  
![equation5](https://user-images.githubusercontent.com/19466939/131537227-bb9c1081-eed2-43e9-aa28-7cbe5aa62ed6.png)  
![equation6](https://user-images.githubusercontent.com/19466939/131537235-6e2b5446-81f0-45ae-bf97-ebc526397843.png)  
Therefore we can just "Get a ticket" first, calculate the `secret` and "Enter Cinema"!

**Solve:**
```
from Crypto.Util.number import inverse
from json import loads, dumps
import hashlib, sys, os, signal, pwn

def find_secret(msg):
    r = int(msg['r'], 16)
    s = int(msg['s'], 16)
    p = int(msg['p'], 16)
    secret = (inverse((r*inverse(s, p)-s),p)*(p-2)) % p
    return secret, p

def get_ticket(code, secret, p):
    y = int(hashlib.sha256(code.encode()).hexdigest(),16)
    r = ((y**2 - 1) * (inverse(secret**2, p))) % p
    s = ((1 + y) * (inverse(secret, p))) % p
    return {'s': hex(s), 'r': hex(r), 'p': hex(p)}

io = pwn.remote("52.149.135.130", 4872)
io.recvuntil(b'>')
io.sendline(b'2')
io.recvuntil(b'Your ticket : ')
ticket = io.recvuntil(b'}')
io.recvuntil(b'>')
io.sendline(b'1')
io.recvuntil(b'Enter the magic word : ')
secret, p = find_secret(loads(ticket))
ans = dumps(get_ticket("Boombastic", secret, int(p)))
io.sendline(str.encode(ans))
print(io.recvline())
io.close()
```

FLAG : **FwordCTF{4ct_l1k3_a_V1P_4nd_b3c0m3_a_V1P}**

Official writeup : https://github.com/MehdiBHA/FwordCTF-2021/tree/main/Boombastic
