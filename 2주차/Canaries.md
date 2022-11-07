# Canaries

---

## 간단요약

> 스택과 sfp사이의 키값을 넣어 인증실패하면 프로그램을 종료하는 보호기법
> 

## 종류

- **Terminator canaries**
    
    > Canary의 값을 문자열의 끝을 나타내는 문자(NULL 0x00, CR 0x0d, LF 0x0a, EOF 0xff)들을 이용해 생성한다.
    > 
    > 
    > Canaries를 우회하기 위해 return address를 쓰기 전에 null 문자를 써야 하는데 strcpy 함수가 null 문자의 위치까지 복사하므로 overflow를 방지할 수 있다.
    > 
    > 그러나 공격자는 잠재적으로 Canary를 알려진 값으로 겹쳐쓰고 정보를 틀린 값으로 제어해서 canary 검사 코드를 통과할 수 있다.
    > 
- **Random canaries**
    
    > Random Canaries는 Canary의 값을 랜덤하게 생성하여 프로그램 초기 설정 시에 전역 변수에 저장한다.
    > 
    > 
    > 해당 메모리를 읽으려고 할 경우 segmentation fault가 발생한다.
    > 
    > 공격자가 canary 값이 저장된 stack address를 알거나 스택의 값을 읽어올 수 있는 프로그램이 있다면 canary의 값을 확인할 수 있다.
    > 
- **Random XOR canaries**
    
    > Canary의 값을 모든 제어 데이터 또는 일부를 사용해 XOR-scramble하여 생성한다.
    > 
    > 
    > Canary 값, 제어 데이터가 오염되면 Canary 값이 틀려진다.
    > 
    > Canary 값을 stack에서 읽어오는 방법이 좀 더 복잡해질뿐, Random canaries와 동일한 취약점을 가지고 있다.
    >