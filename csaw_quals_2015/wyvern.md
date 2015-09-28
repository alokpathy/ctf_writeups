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
[alokpathy@lawn-143-215-63-181 2015]$ file wyvern
wyvern: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=45f9b5b50d013fe43405dc5c7fe651c91a7a7ee8, not stripped
```

Let's run it to see what it actually does.

```bash
[alokpathy@lawn-143-215-63-181 2015]$ ./wyvern 
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
    brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: 
```

It seems to be asking for a "secret." What happens what I just put "AAAA"?

```bash
[alokpathy@lawn-143-215-63-181 2015]$ ./wyvern 
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
    brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: AAAA

[-] You have failed. The dragon's power, speed and intelligence was greater.
```

Looks like we need to get the correct secret before proceeding further. Let's pull up IDA.

```c
//----- (000000000040E120) ----------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST24_4@1
  char v5; // [sp+80h] [bp-140h]@2
  char v6; // [sp+88h] [bp-138h]@1
  char v7; // [sp+A0h] [bp-120h]@1
  char v8; // [sp+A8h] [bp-118h]@1
  char s; // [sp+B0h] [bp-110h]@1
  int v10; // [sp+1BCh] [bp-4h]@1

  v10 = 0;
  std::operator<<<std::char_traits<char>>(6357472LL, 4253308LL);
  std::operator<<<std::char_traits<char>>(6357472LL, 4253335LL);
  std::operator<<<std::char_traits<char>>(6357472LL, 4253362LL);
  std::operator<<<std::char_traits<char>>(6357472LL, 4253390LL);
  std::operator<<<std::char_traits<char>>(6357472LL, 4253441LL);
  std::operator<<<std::char_traits<char>>(6357472LL, 4253504LL);
  fgets(&s, 257, stdin);
  std::allocator<char>::allocator(&v7, 257LL);
  std::string::string(&v8, &s, &v7);
  std::allocator<char>::~allocator(&v7);
  std::string::string((std::string *)&v6, (const std::string *)&v8);
  v3 = start_quest((std::string *)&v6);
  std::string::~string((std::string *)&v6);
  if ( v3 == 4919 )
  {
    std::string::string((std::string *)&v5, (const std::string *)&v8);
    reward_strength((unsigned __int64)&v5);
    std::string::~string((std::string *)&v5);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(6357472LL, 4253532LL);
  }
  v10 = 0;
  std::string::~string((std::string *)&v8);
  return v10;
}
```

Lots of C++ to go through. It seems that ```s``` is our input since there is an ```fgets``` that pulls at most 257 bytes from ```stdin``` into ```s```. The program also copies our input from ```s``` to ```v7``` and passes a pointer to ```v7``` to a function called ```start_quest```. Before we go into that function, what do we want the function to return? The result of ```start_quest``` is stored in ```v3```, which is then compared again 4919. If it is equal to 4919, the function ```reward_strength``` is called. Else, it is not. Just by the name, ```reward_strength``` seems like a fairly intersting function. Let's take a look at that.

```c
__int64 __fastcall reward_strength(unsigned __int64 a1)
{
  char v2; // [sp+38h] [bp-18h]@1
  char v3; // [sp+40h] [bp-10h]@1
  char v4; // [sp+48h] [bp-8h]@1

  std::string::size((std::string *)a1);
  std::string::substr((std::string *)&v2, a1, 0LL);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(
    (std::string *)&v3,
    "\n[+] A great success! Here is a flag{",
    (std::string *)&v2);
  std::operator+<char,std::char_traits<char>,std::allocator<char>>((std::string *)&v4, (const std::string *)&v3, "}\n");
  std::operator<<<char,std::char_traits<char>,std::allocator<char>>(6357472LL, &v4);
  std::string::~string((std::string *)&v4);
  std::string::~string((std::string *)&v3);
  return std::string::~string((std::string *)&v2);
}
```

```"A great success! Here is the flag{"``` is printed out along with some other stuff in this function. This seems like our goal. Thus, we want the function ```start_quest``` to return 4919 (which is, incidentally 0x1337).

Alright, cool. Let's take a look at ```start_quest``` with this goal in mind.

```c
//----- (0000000000404350) ----------------------------------------------------
__int64 __fastcall start_quest(std::string *a1)
{
  __int64 v2; // [sp+0h] [bp-90h]@2
  __int64 v3; // [sp+8h] [bp-88h]@13
  unsigned int v4; // [sp+34h] [bp-5Ch]@11
  unsigned int v5; // [sp+48h] [bp-48h]@9
  bool v6; // [sp+4Fh] [bp-41h]@2
  std::string *v7; // [sp+50h] [bp-40h]@2
  unsigned int *v8; // [sp+58h] [bp-38h]@2
  __int64 *v9; // [sp+60h] [bp-30h]@2
  __int64 *v10; // [sp+68h] [bp-28h]@2
  std::string *v11; // [sp+70h] [bp-20h]@1

  v11 = a1;
  if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
    goto LABEL_13;
  while ( 1 )
  {
    v10 = &v2 - 2;
    v9 = &v2 - 2;
    v8 = (unsigned int *)(&v2 - 2);
    v7 = (std::string *)(&v2 - 2);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_100);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_214);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_266);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_369);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_417);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_527);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_622);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_733);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_847);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_942);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1054);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1106);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1222);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1336);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1441);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1540);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1589);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1686);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1796);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1891);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1996);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2112);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2165);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2260);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2336);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2412);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2498);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2575);
    v6 = std::string::length(v11) - 1LL != legend >> 2;
    if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
      break;
LABEL_13: // 0x404c13
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_100);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_214);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_266);
    std::vector<int,std::arllocator<int>>::push_back((__int64)&hero, (__int64)&secret_369);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_417);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_527);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_622);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_733);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_847);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_942);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1054);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1106);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1222);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1336);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1441);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1540);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1589);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1686);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1796);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1891);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_1996);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2112);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2165);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2260);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2336);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2412);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2498);
    std::vector<int,std::allocator<int>>::push_back((__int64)&hero, (__int64)&secret_2575);
    v3 = std::string::length(v11);
  }
  if ( v6 )
  {
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
      goto LABEL_14;
    while ( 1 )
    {
      *v8 = legend >> 2;
      if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
        break;
LABEL_14:
      *v8 = legend >> 2;
    }
  }
  else
  {
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
      goto LABEL_15;
    while ( 1 )
    {
      std::string::string(v7, v11);
      if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
        break;
LABEL_15:
      std::string::string(v7, v11);
    }
    v5 = sanitize_input(v7);
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
      goto LABEL_16;
    while ( 1 )
    {
      *v8 = v5;
      std::string::~string(v7);
      if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
        break;
LABEL_16:
      *v8 = v5;
      std::string::~string(v7);
    }
  }
  do
    v4 = *v8;
  while ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 );
  return v4;
}
```

Keep in mind that the argument to this function, ```a1```, is our input. Note that there's also an assignment from ```a1``` to ```v11```. 

Note that the condition before the for-loop must be false.
```c
if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
    goto LABEL_13;
```

The reason this ```if``` must not go through is that the exact opposite condition is in an ```if``` within the ```while``` loop.

```c
if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
    break;
```

Why does this matter? The condition on the ```while``` loop is 1, and this is the only ```break``` within the entire loop. So, if this condition ```y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0``` were false, the program would go through an infinite loop. We know that's not the case since we already ran it.

Why is this ```if``` here, anyways? This program is actually obfuscated using LLVM (you can find this out by running ```strings``` on wyvern). LLVM obfuscation does many things to the code, one of which is bogus control flow. This will play a role later on.

The ```while``` loop itself seems to just be adding items to a vector. We'll just keep this fact in mind in case we run into the vector. There are a few other noteworthy statements within the loop:

```c
v6 = std::string::length(v11) - 1LL != legend >> 2;
v3 = std::string::length(v11);
```

The value of ```legend``` is 115 (it's a global variable not shown in the code here). Thus, ```v6``` is simply true if the length of our input without newline is not 28. ```v3``` is just the length of our input with newline.

If ```v6```is true (length of our input is not 28), the function seems essentially just return 28. This is not what we want this function to return, though. This implies that the length of our input must be 28 bytes long.

What happens if ```v6``` is false and our input is 28 bytes long without newline? It copies our input from ```v11``` to ```v7```, calls another function called ```sanitize_input``` and stores the result of that function in ```v5```. It also ultimately returns the value in ```v5```. Thus, our goal is to now get ```sanitize_input```to return 4919 with a 28-byte input since this will get ```reward_strength``` called and print our flag.

Let's delve into ```sanitize_input```.

```c
__int64 __fastcall sanitize_input(std::string *a1)
{
  __int64 v1; // rax@11
  __int64 v2; // rdx@18
  __int64 v3; // rax@23
  __int64 v4; // rsi@41
  __int64 v5; // rax@62
  __int64 v7; // [sp+0h] [bp-180h]@4
  __int64 *v8; // [sp+18h] [bp-168h]@68
  unsigned int v9; // [sp+44h] [bp-13Ch]@65
  __int64 v10; // [sp+48h] [bp-138h]@62
  bool v11; // [sp+52h] [bp-12Eh]@60
  bool v12; // [sp+53h] [bp-12Dh]@54
  bool v13; // [sp+54h] [bp-12Ch]@50
  bool v14; // [sp+55h] [bp-12Bh]@46
  bool v15; // [sp+56h] [bp-12Ah]@46
  __int64 v16; // [sp+80h] [bp-100h]@42
  __int64 v17; // [sp+88h] [bp-F8h]@41
  int v18; // [sp+90h] [bp-F0h]@41
  bool v19; // [sp+96h] [bp-EAh]@38
  bool v20; // [sp+97h] [bp-E9h]@35
  int v21; // [sp+98h] [bp-E8h]@34
  bool v22; // [sp+9Fh] [bp-E1h]@31
  int v23; // [sp+A0h] [bp-E0h]@29
  bool v24; // [sp+A7h] [bp-D9h]@28
  __int64 v25; // [sp+A8h] [bp-D8h]@27
  __int64 v26; // [sp+B0h] [bp-D0h]@26
  bool v27; // [sp+BEh] [bp-C2h]@23
  bool v28; // [sp+BFh] [bp-C1h]@21
  unsigned __int64 v29; // [sp+C0h] [bp-C0h]@20
  bool v30; // [sp+CFh] [bp-B1h]@18
  __int64 v31; // [sp+D0h] [bp-B0h]@18
  bool v32; // [sp+DFh] [bp-A1h]@15
  __int64 v33; // [sp+E0h] [bp-A0h]@11
  bool v34; // [sp+EFh] [bp-91h]@8
  __int64 v35; // [sp+F0h] [bp-90h]@8
  bool v36; // [sp+FEh] [bp-82h]@7
  bool v37; // [sp+FFh] [bp-81h]@5
  __int64 v38; // [sp+100h] [bp-80h]@4
  __int64 v39; // [sp+108h] [bp-78h]@4
  __int64 *v40; // [sp+110h] [bp-70h]@4
  __int64 *v41; // [sp+118h] [bp-68h]@4
  __int64 v42; // [sp+120h] [bp-60h]@4
  __int64 *v43; // [sp+128h] [bp-58h]@4
  __int64 v44; // [sp+130h] [bp-50h]@4
  unsigned int *v45; // [sp+138h] [bp-48h]@4
  __int64 *v46; // [sp+140h] [bp-40h]@4
  bool v47; // [sp+14Fh] [bp-31h]@2
  std::string *v48; // [sp+150h] [bp-30h]@1

  v48 = a1;
  do
    v47 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
  while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
  if ( !v47 )
    goto LABEL_68;
  while ( 1 )
  {
    v46 = &v7 - 2;
    v45 = (unsigned int *)(&v7 - 2);
    v44 = (__int64)(&v7 - 4);
    v43 = &v7 - 2;
    v42 = (__int64)(&v7 - 2);
    v41 = &v7 - 2;
    v40 = &v7 - 2;
    v39 = (__int64)(&v7 - 2);
    v38 = (__int64)(&v7 - 4);
    std::vector<int,std::allocator<int>>::vector((__int64)(&v7 - 4));
    *(_DWORD *)v43 = 0;
    if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
      break;
LABEL_68:
    v8 = &v7 - 2;
    std::vector<int,std::allocator<int>>::vector((__int64)(&v7 - 4));
    *(_DWORD *)v8 = 0;
  }
  while ( 1 )
  {
    do
      v37 = *(_DWORD *)v43 < legend >> 2; // v43 = 0, so v37 is true
    while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 ); // must be false.
    if ( !v37 ) // should not go in here.
    {
      do
        v11 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
        ;
      LODWORD(v5) = std::operator<<<std::char_traits<char>>(6357472LL, 4253236LL);
      v10 = v5;
      if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
        goto LABEL_91;
      while ( 1 )
      {
        *v45 = 4919;
        *(_DWORD *)v41 = 1;
        if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
          goto LABEL_64;
LABEL_91:
        *v45 = 4919;
        *(_DWORD *)v41 = 1;
      }
    }
    do
      v36 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v36 = 1
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ); // must be false.
    do
    {
      do
      {
        v35 = *(_DWORD *)v43; // v35 = 0
        v34 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v34 = 1
      }
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ); // this is false.
    }
    while ( !v34 ); // is false.
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ) // is false.
      ;
    LODWORD(v1) = std::string::operator[](v48, v35); // ith character of input packed into v1.
    v33 = v1;                                        // ith character of input packed into v33.
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 ) // we don't go through here.
    {
LABEL_71:
      if ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
        goto LABEL_114;
      while ( 1 )
      {
        *(_DWORD *)v42 = *(_BYTE *)v33;
        if ( y4 < 10 || (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) == 0 )
          break;
LABEL_114:
        *(_DWORD *)v42 = *(_BYTE *)v33;
      }
    }
    *(_DWORD *)v42 = *(_BYTE *)v33; // v42 is first character of input.
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 ) // is not true.
      goto LABEL_71;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ) // false.
      ;
    std::vector<int,std::allocator<int>>::push_back(v44, v42); // v44 is vector with first character of input.
    do
      v32 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v32 is 1
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ); / false.
    if ( !v32 ) // not gone through.
LABEL_74:
      *(_DWORD *)v39 = *(_DWORD *)v43;
    if ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ) // not gone through.
LABEL_99:
      *(_DWORD *)v39 = *(_DWORD *)v43; 
    v2 = v39;  // unsure of v39 and v2's value.       
    *(_DWORD *)v39 = *(_DWORD *)v43; // v39 is 0
    v31 = *(_DWORD *)v2; // unsure of v31
    v30 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v30 is 1
    if ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ) // false.
      goto LABEL_99;
    if ( !v30 ) // not gone through.
      goto LABEL_74;
    v29 = std::string::length(v48); // length of input.
    do
      v28 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v28 is 1.
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ); // false.
    if ( !v28 ) // not gone through.
LABEL_75:
      *(_DWORD *)v39 = (v29 >> 40) & v31 | 0x1C;
    v3 = v39; // v3 is 0.
    *(_DWORD *)v39 = (v29 >> 40) & v31 | 0x1C; // v39 is 28
    v27 = *(_DWORD *)v3 != 0; // v27 is 0.
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 ) // false.
      goto LABEL_75;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ) // false.
      ;
    if ( v27 ) // *gone through*
    {
      do
        v26 = *(_DWORD *)v43; // v26 is 0
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 ); // false.
      v25 = std::vector<int,std::allocator<int>>::operator[](6357752LL, v26);
      do
        v24 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v24 is 1.
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
      do
        v23 = *(_DWORD *)v25; // v23 is pointer to allocation.
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 );
      std::vector<int,std::allocator<int>>::vector(v38, v44); // v38 is now ith character of input. 
      do
        v22 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
      while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
        ;
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
        ;
      v21 = transform_input(v38); // v21 is result of transform_input on ith character of input.
      if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 ) // not gone through.
        goto LABEL_79;
      while ( 1 )
      {
        v20 = v23 == v21;
        if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
        {
          while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
            ;
          std::vector<int,std::allocator<int>>::~vector(v38);
          do
            v19 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
          while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
          while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
            ;
          if ( v20 )
          {
            do
            {
              v4 = *(_DWORD *)v43;
              v18 = *(_DWORD *)v39;
              v17 = v4;
            }
            while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 );
            v16 = std::vector<int,std::allocator<int>>::operator[](6357752LL, v17);
            if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
              goto LABEL_83;
            while ( 1 )
            {
              *(_DWORD *)v39 = (*(_DWORD *)v16 & v18) < 0;
              if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
                break;
LABEL_83:
              *(_DWORD *)v39 = (*(_DWORD *)v16 & v18) < 0;
            }
          }
          if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
            goto LABEL_84;
          while ( 1 )
          {
            if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
              goto LABEL_46;
LABEL_84:
            while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
              ;
          }
        }
LABEL_79:
        while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
          ;
      }
    }
    do
    {
      do
      {
LABEL_46:
        v15 = *(_DWORD *)v39 != 0; // v15 is 1.
        v14 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v14 is 1.
      }
      while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ); // false.
    }
    while ( !v14 );
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      ;
    if ( v15 )
      break;
    do
      v12 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 );
    while ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
      ;
    while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
      ;
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
LABEL_89:
      ++*(_DWORD *)v43;
    ++*(_DWORD *)v43;
    if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 )
      goto LABEL_89;
  }
  do
    v13 = y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0; // v13 is 1.
  while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 ); // false.
  if ( !v13 ) 
    goto LABEL_87;
  while ( 1 )
  {
    *v45 = ((unsigned __int16)*(_DWORD *)v43 << 8) & 0x147; // v45 is 0.
    *(_DWORD *)v41 = 1;                                     // v41 is 1.
    if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 ) // true.
      break;
LABEL_87:
    *v45 = ((unsigned __int16)*(_DWORD *)v43 << 8) & 0x147;
    *(_DWORD *)v41 = 1;
  }
LABEL_64:
  if ( y18 >= 10 && (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) != 0 ) // not gone through.
    goto LABEL_92;
  while ( 1 )
  {
    std::vector<int,std::allocator<int>>::~vector(v44);
    v9 = *v45; // v9 is 0.
    if ( y18 < 10 || (((_BYTE)x17 - 1) * (_BYTE)x17 & 1) == 0 )
      break;
LABEL_92:
    std::vector<int,std::allocator<int>>::~vector(v44);
  }
  while ( y4 >= 10 && (((_BYTE)x3 - 1) * (_BYTE)x3 & 1) != 0 )
    ;
  return v9;
}
```

This looks like a monstrous function. But, remember what we mentioned earlier about bogus control flow? Stepping through this function will show that a lot of ```sanitize_input``` is completely useless. You can look at the comments I have on the side of many lines here to get the idea of the flow.


Something interesting comes up. It seems like ```sanitize_input``` iterates over every character int he input. It then calls ```transform_input``` on each each character. If ```transform_input``` returns a particular value, then the function stops. If it returns a different value, then we continue to the next character by going back to the beginning of the ```while``` loop. Even more interesting is ```v37``` increments every time we go back to the beginning of the ```while```, and when it reaches 28 (the length of our input), it sets the value pointed to by ```v45``` as 4919. Later on, ```v9``` is set to dereferenced ```v45```, which is then returned. 

So we want to go back to the beginning of the ```while``` loop for each character in the input. To do this, ```transform_input``` must return the correct value for each character in the input. This must mean that ```transform_input``` validates each character in the password by some metric. Thus, ```sanitize_input``` is essentially an obfuscated version of the following:

```c
int sanitize_input(char* input) {
    int i;
    for (i = 0; i < 28; i++) {
        // assumes WLOG that transform_input returns 0
        // when input[i] is incorrect.
        if (!transform_input(input[i])) {
            return 0; 
        }
    }
    return 4919;
}
```
Now, one solution is to obviously look into ```transform_input``` and see what exactly it does. This is a completely valid solution, and I've seen many people go this route (it ends up using some simple rule). But, ```transform_input``` is also obfuscated, and I'm sick of going through so much obfuscated code. There must be a better way.

And there is. Observe that when the first character of the input is correct, far more instructions are executed than when it is incorrect. This is because when the first character is incorrect, ```sanitize_input``` simply returns, but when the first character is correct, it jumps to the beginning of the for loop, increments ```i```, and makes another comparison. Thus, if we input "a" + "A"\*28, "b" + "A"\*28 to ```sanitize_input``` and count the number of instructions the function makes, whichever input makes ```sanitize_input``` make a substantial number of instructions likely has the correct first byte. This can be extended so we can get the first, second, third, ..., and twenty-eighth character of the input easily. Once we have all these characters, we have the password. And we win.

Normally I'd use a tool like [Intel Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) for instruction counting. However, I could not get this to install easily (Fedora did some things with GCC's C++ ABI). So, I simply just added a breakpoint at the beginning of the ```for``` loop and counted how many times the breakpoint was hit. This still works, but it just takes a much longer time (O(n^2) really). In any case, we still get the flag: ```dr4g0n_or_p4tric1an_it5_LLVM```.

```bash
 [alokpathy@lawn-143-215-63-181 2015]$ ./wyvern 
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
    brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: dr4g0n_or_p4tric1an_it5_LLVM
success

[+] A great success! Here is a flag{dr4g0n_or_p4tric1an_it5_LLVM}
```
