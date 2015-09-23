#CSAWCTF 2015 Quals: wyvern

----------
## Challenge details
Category: Reversing 

Points:   500

**Description:**
>*There's a dragon afoot, we need a hero. Give us the dragon's secret and we'll give you a flag.*
>
>*[wyvern_c85f1be480808a9da350faaa6104a19b](challenge/contacts)*

## Writeup

We're given a 64-bit LSB executable, nothing that uncommon for a CTF reversing problem.

```bash
file wyvern
wyvern: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=45f9b5b50d013fe43405dc5c7fe651c91a7a7ee8, not stripped
```
