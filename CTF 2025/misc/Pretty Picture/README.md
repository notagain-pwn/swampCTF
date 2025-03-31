---
title: "Pretty Picture: Double Exposure 🌈 – Misc Challenge (SwampCTF 2025)"
tags: [CTF, MISC, Stego, Image Analysis, AperiSolve, SwampCTF]
---

# Pretty Picture: Double Exposure 🌈

![Category](https://img.shields.io/badge/Category-Misc-blue)
![Technique](https://img.shields.io/badge/Stego-Image_Analysis-orange)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![Event](https://img.shields.io/badge/CTF-SwampCTF%202025-purple)

> Hidden in the bits below, an image wait's to be shown.

Sometimes, a picture really is worth a thousand hidden bits 📸🕵️

## 📚 Table of Contents

- [Challenge Overview 📦](#challenge-overview-)
- [Solving Approach 🤖](#solving-approach-)
- [Tool Used 🔧](#tool-used-)
- [Flag 📋](#flag-)

## Challenge Overview 📦

In "Pretty Picture: Double Exposure", we’re given an image and a vague hint that something might be hidden within.

![double-exposure](https://github.com/user-attachments/assets/90ed06fe-79dc-4532-bc02-2000b6457ccb)

No password, no extra info — just a file and the category: *MISC*.

## Solving Approach 🤖

When faced with image challenges, the go-to strategy is to run it through automated forensic tools. 

In this case, the solution was straightforward:

- Upload the image to **[AperiSolve](https://aperisolve.fr/)**
- Click “Submit”
- Review the extracted layers, metadata, and analysis output

Boom — the flag is revealed in the visual output.

![output one](https://github.com/user-attachments/assets/8170f19a-b350-4975-9e6a-83c0f5b80809)

![output two](https://github.com/user-attachments/assets/d46e234d-43a0-4f7a-86db-3d9c67770705)

## Tool Used 🔧

**AperiSolve**  
> [https://aperisolve.fr](https://aperisolve.fr)

This free online tool automates forensic analysis on images, using a ton of useful techniques:
- Strings
- Layers
- Metadata
- Steg detection

It’s incredibly useful for fast MISC/STEGO triage in CTFs.

![output three](https://github.com/user-attachments/assets/b11541ae-ad69-4e67-bbfc-99bc5c1c98a3)

## Flag 📋

```
swampCTF{m3ss4g3s_0r_c0de_c4n_b3_h1dd3n_1n_1m4g3s}
```

🔙 [Back to SwampCTF 2025 Writeups](../../)
