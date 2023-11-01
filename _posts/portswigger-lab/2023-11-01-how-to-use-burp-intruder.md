---
layout: post
title: How to Use Burp Intruder - Postswigger Web Security Academy Lab "Username enumeration via different responses"
tags: [Notes, PortSwigger, web]
---

~~long time no see~~

>  This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:
>
> - [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
> - [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)
> 
> To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

1. Open the web page using the browser included in Burp Suite and find the corresponding HTTP request. In this challenge, the target is `POST /login`.

![]({{"/assets/img/posts/burp-intruder/1.png" | relative_url}}){:style="display: block; margin: auto"}

2. Select the request and send it to Intruder by ctrl+I.

![]({{"/assets/img/posts/burp-intruder/2.png" | relative_url}}){:style="display: block; margin: auto"}

3. ("Positions" tab) Choose one of the four attack types
- One set of payload, one or more payload positions
  - Sniper: Places each payload into the first position, then the second position, and so on.
  - Battering Ram: Places each payload into all positions.
- Multiple sets of payload, different payload sets for different payload positions
  - Pitchfork: Iterates through all payload sets simultaneously.
  - Cluster Bomb: All permutations of payload combinations are tested.

1. ("Positions" tab) Set payload positions by marking the position in the base request. In this challenge, we are bruteforcing `username` first.

![]({{"/assets/img/posts/burp-intruder/3.png" | relative_url}}){:style="display: block; margin: auto"}

5. ("Payload" tab) Paste the payload.

![]({{"/assets/img/posts/burp-intruder/4.png" | relative_url}}){:style="display: block; margin: auto"}

6. ("Settings" tab) If you want to extract extra data from response, you can checkout "Grep - Extract". In this challenge, we are guessing that the "Invalid username" prompt will change to something else if we guess the username correctly.

![]({{"/assets/img/posts/burp-intruder/5.png" | relative_url}}){:style="display: block; margin: auto"}

7. Start the attack! There will be a popup window showing the results of the attack. And... yeah, we find something different.

![]({{"/assets/img/posts/burp-intruder/6.png" | relative_url}}){:style="display: block; margin: auto"}

This covers the basic usage of Burp Intruder. Now we know the correct username, we can brute force the password again and get in!
