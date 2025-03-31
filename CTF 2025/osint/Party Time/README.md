---
title: "Party Time 🎉 – EXIF OSINT (SwampCTF 2025)"
tags: [CTF, OSINT, EXIF, Geolocation, Metadata, SwampCTF]
---

# Party Time 🎉

![OSINT](https://img.shields.io/badge/OSINT-✔️-brightgreen)
![Metadata](https://img.shields.io/badge/EXIF-GPS-blue)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![Category](https://img.shields.io/badge/Category-OSINT-orange)
![Event](https://img.shields.io/badge/CTF-SwampCTF%202025-purple)

> This party house is known for its 3AM outings, but you've gotta work for the location if you want to come! Enter the GPS coordinates of the location!

> Example: swampCTF{xx.xx.xx,xx.xx.xx}, swampCTF{xx.xx, xx.xx}

Who needs an invitation when you can extract the GPS location from a party pic? 🍻📷

## 📚 Table of Contents

- [Challenge Overview 📦](#challenge-overview-)
- [Step 1: Analyzing the Image Metadata 📏](#step-1-analyzing-the-image-metadata-)
- [Step 2: Reverse Image/Location Search 🔎](#step-2-reverse-imagelocation-search-)
- [Step 3: Confirming Location and Submitting Flag 🌐](#step-3-confirming-location-and-submitting-flag-)
- [Flag 📋](#flag-)

## Challenge Overview 📦

The challenge "Party Time!" from SwampCTF 2025 dropped us an image and a simple instruction:

> This party house is known for its 3AM outings, but you've gotta work for the location if you want to come!

> Enter the GPS coordinates of the location!

So we’re hunting for GPS data hidden inside the image.

## Step 1: Analyzing the Image Metadata 📏

![IMG_4048](https://github.com/user-attachments/assets/541a177c-52a4-4fa8-874f-eff524bcafd3)

I used the classic tool `exiftool` to extract metadata from the image file.

```
exiftool IMG_4048.jpg
```

Inside the output, we found embedded GPS coordinates!

![GPS coordinates](https://github.com/user-attachments/assets/5581e80d-27a6-4bc6-ae7f-5fb7f087f44c)

## Step 2: Reverse Image/Location Search 🔎

Pasting the coordinates `29°39'10.3"N 82°19'59.7"W` into Google Maps shows us a house that looks *very* similar to the one in the provided image.

![Google image](https://github.com/user-attachments/assets/2c23eb4b-63f4-47e9-9a89-a98562abd2a7)

We’re confident we’ve found the right party house.

## Step 3: Confirming Location and Submitting Flag 🌐

I trimmed the coordinates to two decimal places, as suggested by the challenge format:

Formula:
- `Decimal = Degrees + (Minutes / 60) + (Seconds / 3600)`

```
= 29 + 39/60 + 10.32/3600
= 29 + 0.65 + 0.002867
= 29.652867
```

And: 

```
= 82 + 19/60 + 59.68/3600
= 82 + 0.316667 + 0.016577
= 82.333244
```

```
swampCTF{29.65,-82.33}
```

✅ Flag accepted!

## Flag 📋

```
swampCTF{29.65,-82.33}
```

Easy and fun use of metadata in classic OSINT fashion — and a reminder that photos can carry more info than you think 📸🔍

🔙 [Back to SwampCTF 2025 Writeups](../../)
