---
title: "Hidden Message Board 🕵️‍♀️ – React DOM Injection (SwampCTF 2025)"
tags: [CTF, web, react, javascript, DOM injection]
---

# Hidden Message Board 🕵️‍♀️

![web](https://img.shields.io/badge/category-Web-blue)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)
![CTF](https://img.shields.io/badge/Event-SwampCTF%202025-purple)

> Somewhere on this message-board is a hidden flag. Nothing has worked so far but we have noticed a weird comment in the HTML. Maybe it's a clue?

HackerChat is a React message board… but is it secure?

This challenge is a great introduction to debugging React apps, understanding client-side rendering logic, and manipulating the DOM in a way that bypasses React’s internal state checks.

## 📚 Table of Contents

- [Challenge Overview 🧩](#challenge-overview-)
- [Static Clue in the Source 🔍](#static-clue-in-the-source-)
- [React Internals & Flag Logic 🧠](#react-internals--flag-logic-)
- [The Trick: DOM + Event Injection 🎯](#the-trick-dom--event-injection-)
- [Final Script 🧪](#final-script-)
- [Conclusion 🚪](#conclusion-)

## Challenge Overview 🧩

We’re given access to a simple-looking React app hosted at:

```
http://chals.swampctf.com:43333/
```

The interface lets you type and post messages. Nothing obviously special.

## Static Clue in the Source 🔍

When inspecting the page’s source or using the browser debugger (e.g. DevTools), we notice:

```html
<div id="flagstuff" code=""></div>

<div style={{display:'none'}}>
  Need to remove flagstuff. code: G1v3M3Th3Fl@g!!!!
</div>
```

Interesting. Looks like there’s a secret "code" value the app is checking for.

## React Internals & Flag Logic 🧠

Looking deeper into the app logic, we find the `App()` component contains some interesting stuff:

```javascript
const [flagGoesHere, setFlagValue] = useState("");
...
if (printFlagSetup.getAttribute("code") === "G1v3M3Th3Fl@g!!!!") {
  const flag = await getFlag();
  setFlagValue("[flag]: " + flag);
}
```

![App js start](https://github.com/user-attachments/assets/dcb155f2-aae6-4692-b199-6f0fa46fa428)

![App js check code](https://github.com/user-attachments/assets/bc8cf950-b858-4cc7-b245-90fd00ba5f73)

![App js display flag](https://github.com/user-attachments/assets/95a6cba4-4f67-4f32-a1c2-173f4640838b)

So if the `<div id="flagstuff">` has its `code` attribute set to the right value, the app fetches and displays the flag via `setFlagValue`.

But React doesn’t watch for raw DOM mutations like `setAttribute()` — it relies on its own virtual DOM and event system.

## The Trick: DOM + Event Injection 🎯

To **force React to re-evaluate the logic**, we:

1. Set the right attribute:
```js
document.getElementById("flagstuff").setAttribute("code", "G1v3M3Th3Fl@g!!!!");
```

2. But this alone isn't enough — we need to simulate **input activity** to trigger the check logic again.

That means we must:
- Use the native `value` setter (so React recognizes it)
- Dispatch a real `"input"` event

## Final Script 🧪

Paste this in your browser console (on the challenge site):

```js
(function () {
  const FLAG_CODE = "G1v3M3Th3Fl@g!!!!";

  // 1. Modify the flag div
  const flagDiv = document.getElementById("flagstuff");
  if (flagDiv) {
    flagDiv.setAttribute("code", FLAG_CODE);
    console.log("[+] code attribute set");
  } else {
    console.error("[-] flagstuff not found");
    return;
  }

  // 2. Trigger a legitimate React input event
  const textarea = document.querySelector("textarea");
  if (textarea) {
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
    nativeInputValueSetter.call(textarea, " ");

    const inputEvent = new Event("input", { bubbles: true });
    textarea.dispatchEvent(inputEvent);

    console.log("[+] triggered real input event");
  } else {
    console.error("[-] textarea not found");
  }
})();
```

Once executed, the app will internally re-run `checkCode()` and call `getFlag()`. 

The flag will appear on the page under `[flag]: ...`.

![Flag on website](https://github.com/user-attachments/assets/cbfd8311-81ba-4602-987a-16cdc4438bff)

`[flag]: swampCTF{Cr0ss_S1t3_Scr1pt1ng_0r_XSS_c4n_ch4ng3_w3bs1t3s}`

### Another simple approach

We can also look inside the code source directly, in: http://chals.swampctf.com:43333/static/js/bundle.js

By searching `flag.txt`, we can find these lines of code: 

```
/***/ "./src/HiddenData/flag.txt":
/*!*********************************!*\
  !*** ./src/HiddenData/flag.txt ***!
  \*********************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";
module.exports = __webpack_require__.p + "static/media/flag.d93dd6a8616cc31d36db.txt";
```

![Flag txt](https://github.com/user-attachments/assets/93ad177c-3cd7-40af-b1be-c1716c8675c8)

And we can simply retrieve the flag here: http://chals.swampctf.com:43333/static/media/flag.d93dd6a8616cc31d36db.txt

But less funny than the other approach, lol.

## Conclusion 🚪

This challenge highlights:

- Why DOM manipulation in React apps isn’t always enough
- How to simulate events and state to trigger side effects
- The importance of analyzing both UI and JS code

🧠 **Takeaway**: Frontend logic can hide secrets — and JavaScript is your lockpick!

🔙 [Back to SwampCTF 2025 Writeups](../../)
