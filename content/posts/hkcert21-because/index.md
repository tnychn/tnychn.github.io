---
title: "HKCERT CTF 2021: 因講了出來 Because I Said It"
description: ""
date: 2021-11-16T02:00:32+08:00
lastmod: 2021-11-16T02:00:32+08:00
math: false
draft: false
tags: ["ctf", "hkcert21", "web", "php"]
---

> **This post is part of the [HKCERT 2021 CTF series](/tags/hkcert21).**

---

|     Name     | 因講了出來 (Because I Said It)   |
| :----------: | -------------------------------- |
|     Tags     | web                              |
|    Points    | 150                              |
|  Difficulty  | ★☆☆☆☆                            |
|    Solves    | 76 (total of all four divisions) |
| Release Date | 2021-11-12 13:00:00              |

> If you can solve Rickroll in 2020, you will be able to solve it. Probably.
>
> The PHP version used for the challenge is 8.0.12.
>
> http://chalf.hkcert21.pwnable.hk:28156/

{{< figure src="1.png" width=300 >}}

---

## Analysis

The first thing we did was clicking into the *Check Here* link intuitively. It redirects us to `/source.php` where we can see the PHP source code of the page.

```php
session_start();

if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: welcome.php");
    exit;
}

$username = $password = "";
$username_err = $password_err = $login_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST"){

    if ((strlen($_POST["username"]) > 24) or strlen($_POST["password"]) > 24) {
        header("location: https://www.youtube.com/watch?v=2ocykBzWDiM");
        exit();
    }

    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter username.";
    } else{
        $username = trim($_POST["username"]);
        if(empty(trim($_POST["password"]))){
            $password_err = "Please enter your password.";
        } else{
            $password = trim($_POST["password"]);
            if (!ctype_alnum(trim($_POST["password"])) or !ctype_alnum(trim($_POST["username"]))) {
                switch ( rand(0,2) ) {
                    case 0:
                    header("location: https://www.youtube.com/watch?v=l7pP3ydt3tU");
                    break;
                    case 1:
                    header("location: https://www.youtube.com/watch?v=G094II5gIsI");
                    break;
                    case 2:
                    header("location: https://www.youtube.com/watch?v=0YQtsez-_D4");
                    break;
                    default:
                    header("location: https://www.youtube.com/watch?v=2ocykBzWDiM");
                    exit();
                }   
            }
        }
    }    

    if ($username === 'hkcert') {
        if( hash('md5', $password) == 0 &&
            substr($password,0,strlen('hkcert')) === 'hkcert') {
            if (!exec('grep '.escapeshellarg($password).' ./used_pw.txt')) {

                $_SESSION["loggedin"] = true;
                $_SESSION["username"] = $username;

                $myfile = fopen("./used_pw.txt", "a") or die("Unable to open file!");
                fwrite($myfile, $password."\n");
                fclose($myfile);
                header("location: welcome.php");

            } else {
                $login_err = "Password has been used.";
            }

        } else {
            $login_err = "Invalid username or password.";
        }
    } else {
        $login_err = "Invalid username or password.";
    }
}
```

The procedure of this login page is very typical, getting the inputs from an HTML form and then sending a HTTP POST request to server with the credentials as the payload. But there are some special conditions required for the credentials in order to log into the page. If the credentials do not pass the criterions, an error message is shown on the HTML.

1. **Line 14:** both the lengths of username and password must not exceed 24 characters
{{< highlight php "linenostart=14" >}}
if ((strlen($_POST["username"]) > 24) or strlen($_POST["password"]) > 24)
{{< / highlight >}}
2. **Line 19 & Line 23:** both username and password must not be empty
{{< highlight php "linenostart=19" >}}
if(empty(trim($_POST["username"])))
{{< / highlight >}}
{{< highlight php "linenostart=23" >}}
if(empty(trim($_POST["password"])))
{{< / highlight >}}
3. **Line 27:** both username and password must be alphanumeric
{{< highlight php "linenostart=27" >}}
if (!ctype_alnum(trim($_POST["password"])) or !ctype_alnum(trim($_POST["username"])))
{{< / highlight >}}
4. **Line 46:** `username === "hkcert"` (triple equality: exact equal, same type and same value)
{{< highlight php "linenostart=46" >}}
if ($username === 'hkcert')
{{< / highlight >}}
5. **Line 47:**  `the md5 hash of password == 0` (mind the double equality used here, we will talk about this later)
{{< highlight php "linenostart=47" >}}
(hash('md5', $password) == 0)
{{< / highlight >}}
6. **Line 48:** password must start with a "hkcert" prefix
{{< highlight php "linenostart=48" >}}
(substr($password,0,strlen('hkcert')) === 'hkcert')
{{< / highlight >}}
7. **Line 49:** the UNIX `grep` command is used here to search if the exact same password already exists in the `./used_pw.txt` file;
This means we cannot reuse the passwords previously used by other teams that solved this challenge.
{{< highlight php "linenostart=49" >}}
if (!exec('grep '.escapeshellarg($password).' ./used_pw.txt'))
{{< / highlight >}}

**From *Point 4*, we can already conclude that the username required is `hkcert` without a doubt.**

Now, we need to figure out the password. First, let's take a look at *Point 7*. If we navigate to `/used_pw.txt`, we can see a plain text with passwords on each line.

```toml
# the below line is probably for identification purpose?
# can be ignored anyways as we are using grep to search the file
hkcertctf21

hkcert1513101299
hkcert1485194470
hkcert_fcuk054389891
hkcertctf228191174
```

First thing you will notice is that all the passwords have the `hkcert` prefix. This conforms *Point 6*.

Now if you try md5 hashing each of these passwords, you might already notice another common characteristic among all these passwords.

```toml
hkcert1513101299  # 0e943391270105244747709215219780
hkcert1485194470  # 0e758523168817202461901834539918
hkcert_fcuk054389891  # 0e960908643632998868593805082813
hkcertctf228191174  # 0e831500119534187998113976784254
```

Can you see it? All of the hashes have a `0e` prefix and a bunch of digits. These are all scientific numbers with base 0.

Why is that? Remember the double equality we mentioned in *Point 5*?

## PHP Loose Comparison & Type Juggling

The `==` double equality sign in PHP is for loose comparison. When comparing a string to a number, PHP will attempt to convert the string to a number then perform a numeric comparison. The type conversion before comparing is called *type juggling*.

Now if we take a look of the official PHP [manual](https://www.php.net/manual/en/function.md5.php) of the `md5` function, we can find something interesting in the "User Contributed Notes" section.

> **Comment by Ray Paseur**
>
> md5('240610708') == md5('QNKCDZO')
>
> This comparison is true because both md5() hashes start '0e' so PHP type juggling understands these strings to be scientific notation.  By definition, zero raised to any power is zero.

This means if we loose compare a string `"0e123456789"` with an integer `0`, the result is `true`.

## The Exploit

Now that we understand the weakness of loose comparison, we can make use of this to do the exploit.

In *Point 5*, since the source code is loose comparing the md5 hash string of the password with integer 0, if we can find a string with a md5 hash that matches the pattern `/^0+e[0-9]+$/`, the if-condition will return true, hence logging us into the page.

For this purpose, I wrote a simple Python script to brute force the password.

```python
import hashlib
import random

i = 1 # try incrementally with a number, starting from 1
s = "lol" # prepend with "lol" to increase chance of success, and to prevent getting a used password by other teams
prefix = "hkcert"  # Point 6

while True:
    password = prefix + str(i)
    print(password + "\r", end="")  # uses "\r" to avoid spamming the stdout

    # Point 1
    if len(password) > 24:
        print("length exceeded")
        break

    # get the md5 hash
    out = hashlib.md5(password.encode('utf-8')).hexdigest()

    # Point 5
    if out.startswith("0e") and out[2:].isdigit():
        print(password)  # print the result
        print(out)
        break

    i += 1
```

Here was the output of the script.

```
$ python3 solve.py                         09:02:00 PM
hkcertlol247360143
0e177940692660666190029640266163
$                                  59m 42s 10:01:44 PM
```

I plugged the charger into my 2016 MacBook Pro, went to sleep and keep the script running. The script spent almost an hour to find the result. I knew there were faster ways, but since our team was running out of time, I didn't think much. When I woke up a few hours later, I had already got the result.

Anyway, we now log in with username `hkcert` and password `hkcertlol247360143` from the login page, we will be successfully logged into a page showing the flag `hkcert21{php_da_b3st_l4ng3ag3_3v3r_v3ry_4ws0m3}`. /s PHP is the best language ever, very awesome!
