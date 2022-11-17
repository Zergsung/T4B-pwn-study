# [pwnable.kr] fd writeup

# C 코드

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;
}
```

## 코드설명

c언어코드를 살펴보면 문자열을 입력받고, 입력받은 문자열을 atoi함수로 정수로 변환해준 다음, 0x1234를 뺀 값을 fd에다가 저장해주는 거 같다.

그리고 read 함수로 buf에다가 값을 입력받고 len에다가도 넣어주는걸 볼 수 있다. 아까 계산한 값을 넣은 fd값을 read함수의 파일디스크립터로 쓰는걸 볼수있다. 이때 우리가 값을 입력하려면 파일디스크립터 값이 **표준입력**인 0이어야 한다. 고로 우린 0x1234(10진수로4660)를 입력해줘야 한다.

그리고 if 문을 보면 우리가 입력한 값이랑 "LETMEWIN"이라는 문자열하고 비교해주는걸 볼수있다. 입력한 값이랑 문자열이랑 같다면 플래그를 읽어주는 거 같다. 한번 접속해서 실행해보자!

# 터미널

```bash
fd@pwnable:~$ ls
fd  fd.c  flag
fd@pwnable:~$ ./fd 4660
LETMEWIN
good job :) #성공적으로 플래그가 나온모습이다
mommy! I think I know what a file descriptor is!!
```