---
title: "Beginner Web 🌐 – AES Decryption in the Browser (SwampCTF 2025)"
tags: [CTF, web, javascript, browser, AES, crypto, source inspection]
---

# Beginner Web 🌐

![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Category](https://img.shields.io/badge/category-Web-orange)
![CTF](https://img.shields.io/badge/Event-SwampCTF%202025-purple)
![JS](https://img.shields.io/badge/Javascript-✔️-brightgreen)
![AES](https://img.shields.io/badge/AES-Decryption-success)

> Hey, my son Timmy made his first website. He said he hid a 'secret' message within different parts of the website... can you find them all? I wanna make sure he isn't saying any swear words online.

> The flag is broken up into 3 parts. The parts of the flag should be concatenated in the order they are numbered and then surrounded by the standard wrapper. 

> For example: 'swampCTF{' + part1 + part2 + part3 + '}'

“Sometimes, the flag is right there... just a few decryptions away.”

## 📚 Table of Contents

- [Challenge Overview 📦](#challenge-overview-)
- [Source Code Inspection 🔍](#source-code-inspection-)
- [Finding the Encrypted Data 🔐](#finding-the-encrypted-data-)
- [Decrypting with CryptoJS 🔓](#decrypting-with-cryptojs-)
- [Final Flag 🏁](#final-flag-)
- [Conclusion 🧠](#conclusion-)

## Challenge Overview 📦

We are given a simple URL:

```
http://chals.swampctf.com:42222/
```

There’s no obvious flag or login, but the description suggests checking the source. 

Simply by going to `view-source:http://chals.swampctf.com:42222/`, we have the first part: 

![First part](https://github.com/user-attachments/assets/8b703e93-9242-4619-b204-fd9c712d70c9)

`<!--Part 1 of the flag: w3b_"-->`

## Source Code Inspection 🔍

If we dig dipper in the sources, we discover some JavaScript files, like http://chals.swampctf.com:42222/main-34VY7I6V.js.

We can copy paste the js in https://beautifier.io/ for example. 

After some research, we can find these interesting lines of code: 

![Part 2 and 3](https://github.com/user-attachments/assets/a85cdc3c-c6b1-43b8-b0d8-407f45f30244)

## Finding the Encrypted Data 🔐

 Encrypted parts of the flag using CryptoJS AES:

```js
let n = "flagPart2_3",
    r = "U2FsdGVkX1/oCOrv2BF34XQbx7f34cYJ8aA71tr8cl8",
    o = "U2FsdGVkX197aFEtB5VUIBcswkWs4GiFPal6425rsTU";

const flagPart1 = "w3b_"
```

The variables `r` and `o` represent AES-encrypted parts of the flag, with key `n = "flagPart2_3"`.

## Decrypting with CryptoJS 🔓

We can simply create a local html file, load the crypto library, and re-use these values to decrypt the two other parts of the flag:

```html
<!DOCTYPE html>
<html>
<head>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
</head>
<body>
  <script>
    const key = "flagPart2_3";
    const encryptedPart2 = "U2FsdGVkX1/oCOrv2BF34XQbx7f34cYJ8aA71tr8cl8";
    const encryptedPart3 = "U2FsdGVkX197aFEtB5VUIBcswkWs4GiFPal6425rsTU";

    const part2 = CryptoJS.AES.decrypt(encryptedPart2, key).toString(CryptoJS.enc.Utf8);
    const part3 = CryptoJS.AES.decrypt(encryptedPart3, key).toString(CryptoJS.enc.Utf8);

    const flag = `swampCTF{w3b_${part2}_${part3}}`;
    console.log("[+] Flag:", flag);
    document.body.innerText = flag;
  </script>
</body>
</html>
```

## Final Flag 🏁

Result of our html file:

![Flag](https://github.com/user-attachments/assets/ffe6a7b0-fd47-4e46-9384-8bbe2f906b43)

```
swampCTF{w3b_br0w53r5_4r3_c0mpl1c473d}
```
## Conclusion 🧠

This challenge is a great reminder of how broken encryption setups can completely defeat the purpose of cryptography when misused.

Key takeaways:
- 🔐 **AES in ECB mode is insecure** — it encrypts data in fixed-size blocks without randomization (no IV), making it predictable and reversible when the key is known.
- 🤦‍♂️ Hardcoding the **decryption key in client-side JavaScript** is basically leaving the key under the doormat.
- 🕵️‍♀️ A quick static analysis and one line of decryption later… and the **flag is yours**.

A perfect warmup web challenge to reinforce the idea that **security through obscurity is no security at all 🔓**

🔙 [Back to SwampCTF 2025 Writeups](../../)
