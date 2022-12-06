# NX & ASLR

---

목차

1. [ASLR](https://www.notion.so/NX-ASLR-f7e256b8f6254367b9de747622843b53)
2. [NX](https://www.notion.so/NX-ASLR-f7e256b8f6254367b9de747622843b53)

# ASLR

**ASLR(Address Space Layout Randomization)이란?**

> 바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등을 임의의 주소에 할당하는 보호 기법
이다.
> 

ASLR은 커널에서 지원하는 보호 기법이며, 다음의 명령어로 확인할 수 있습니다.

```bash
$ cat /proc/sys/kernel/randomize_va_space
2
```

리눅스에서 이 값은 0, 1, 또는 2의 값을 가질 수 있습니다. 각 ASLR이 적용되는 메모리 영역은 다음과 같습니다.

- 0(No ASLR) : ASLR을 적용하지않음.
- 1(Conservative Randomization) : 스택, 힙, 라이브러리, vdso 등
- 2(Conservative Randomization + brk) : (1)의 영역과 `brk`로 할당한 영역

아래 코드를 예제로 ASLR의 특징을 살펴보자.

```c
// Name: addr.c
// Compile: gcc addr.c -o addr -ldl -no-pie -fno-PIE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  char buf_stack[0x10];                   // 스택 버퍼
  char *buf_heap = (char *)malloc(0x10);  // 힙 버퍼

  printf("buf_stack addr: %p\n", buf_stack);
  printf("buf_heap addr: %p\n", buf_heap);
  printf("libc_base addr: %p\n",
         *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 주소

  printf("printf addr: %p\n",
         dlsym(dlopen("libc.so.6", RTLD_LAZY),
               "printf"));  // 라이브러리 함수의 주소

  printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```

### ASLR의 특징

위 코드는 메모리의 주소를 출력하는 코드이다. 컴파일 후 실행하면 아래 같은 결과가 나온다.

```bash
$ gcc addr.c -o addr -ldl -no-pie -fno-PIE

$ ./addr
buf_stack addr: 0x7ffcd3fcffc0
buf_heap addr: 0xb97260
libc_base addr: 0x7fd7504cd000
printf addr: 0x7fd750531f00
main addr: 0x400667

$ ./addr
buf_stack addr: 0x7ffe4c661f90
buf_heap addr: 0x176d260
libc_base addr: 0x7ffad9e1b000
printf addr: 0x7ffad9e7ff00
main addr: 0x400667

$ ./addr
buf_stack addr: 0x7ffcf2386d80
buf_heap addr: 0x840260
libc_base addr: 0x7fed2664b000
printf addr: 0x7fed266aff00
main addr: 0x400667
```

스택 영역의 `buf_stack`, 힙 영역의 `buf_heap`, 라이브러리 함수 `printf`, 코드 영역의 함수 `main`, 그리고 라이브러리 매핑 주소 `libc_base`가 출력되었습니다. 

결과를 살펴보면 다음과 같은 특징이 있습니다.

- 코드 영역의 `main`함수를 제외한 다른 영역의 주소들은 실행할 때마다 변경됩니다.실행할 때 마다 주소가 변경되기 때문에 바이너리를 **실행하기 전에 해당 영역들의 주소를 예측할 수 없습니다**.
- 바이너리를 반복해서 실행해도 `libc_base` 주소 하위 12비트 값과 `printf` 주소 하위 12비트 값은 변경되지 않습니다.리눅스는 ASLR이 적용됐을 때, 파일을 **페이지(page)** 단위로 임의 주소에 매핑합니다. 따라서 페이지의 크기인 12비트 이하로는 주소가 변경되지 않습니다.
- `libc_base`와 `printf`의 주소 차이는 항상 같습니다.ASLR이 적용되면, 라이브러리는 임의 주소에 매핑됩니다. 그러나 라이브러리 파일을 그대로 매핑하는 것이므로 매핑된 주소로부터 라이브러리의 다른 심볼들 까지의 거리(Offset)는 항상 같습니다.

```bash
>>> hex(0x7fd7504cd000 - 0x7fd750531f00) # libc_base addr - printf addr
'-0x64f00'
>>> hex(0x7ffad9e1b000 - 0x7ffad9e7ff00)
'-0x64f00'
```

---

# NX

**NX(No-eXecute)란?**

> 실행에 사용되는 메모리 영역과 쓰기에 사용되는 메모리 영역을 분리하는 보호 기법입니다.
> 

어떤 메모리 영역에 대해 쓰기 권한과 실행 권한이 함께 있으면 시스템이 취약해지기 쉽습니다. 예를 들어, 코드 영역에 쓰기 권한이 있으면 공격자는 코드를 수정하여 원하는 코드가 실행되게 할 수 있고, 반대로 스택이나 데이터 영역에 실행 권한이 있으면 Return to Shellcode와 같은 공격을 시도할 수 있습니다.

NX가 적용된 바이너리는 실행될 때 각 메모리 영역에 필요한 권한만을 부여받습니다.

![Untitled](/5%EC%A3%BC%EC%B0%A8/img/NX%26ASLR.png)