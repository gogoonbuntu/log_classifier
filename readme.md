회사에서 일회성으로 사용한 로그파싱 프로그램.

로그에 남겨진 url 쿼리를 파싱해서 인코딩하는 협력사와 하지않는 협력사를 색출해낸다.

신기한 것은 POST 방식으로 전달하는데 뒤에 ? 를 붙여서 쿼리문을 전달하는 회사가 굉장히 많다는 것;

배운 점:
# 퍼센트 인코딩
url 로 넘길 때 사용불가한 특수문자들이 많다.
이 때 퍼센트(%) 인코딩을 쓰게 되는데,
아래 비예약문자들을 제외한 모든 문자들을 인코딩해줘야한다.

### 비예약문자
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
a b c d e f g h i j k l m n o p q r s t u v w x y z
0 1 2 3 4 5 6 7 8 9 - _ . ~

### 예약문자
! * ' ( ) ; : @ & = + $ , / ? # [ ]
그 외 모든 한글
<hr>

# 정규표현식
url의 인코딩 됐는지 여부를 확인할 때 어떻게 필터링 해야할까?
정규표현식을 사용했다.
[^\w\s\-\_\.\~\%\=] 를 사용했다.
\w : 모든 문자와 숫자
\s : 모든 공백문자
[ ] 한 캐릭터
\* 직전의 0번 이상의 반복

이정도를 사용했다.

% 와 = 는 비예약문자가 아니지만, 인코딩된 결과물에서 %가 포함되고, & 로 쿼리를 파싱했다면 VAR=VALUE 형태이기 때문에 =가 포함된다.

# 파이썬 최적화
로그파일만해도 62개요, 한 로그당 순수 문자열만해서 70MB - 90MB 사이즈였다.
속도가 굉장히 중요해지는 프로그래밍이다.

. 을 사용하면 실행시간이 크게 늘어난다.
이를 반복문 전에 미리 선언해놓으면 실행시간이 매우 매우 단축된다. (대략 30% 정도 줄어든다)

```python
a = []
for i in rage(1000000):
  a.append(i)
```
를 사용한다고 예를 든다면, for문 전에 a.append 를 미리 선언하는 것이다.
```python
a = []
ap = a.append
for i in rage(1000000):
  ap(i)
```
로 바꾸면 10초 걸리는 것이 7초로 줄어든다.

# 정규표현식 최적화
졍규표현식은 배열을 일일히 맞춰서 비교할 것 같아서 매우 시간이 오래 걸릴 것으로 생각했으나
생각보다 느리진 않았다.  
match() 함수와 findall() 함수를 비교해본 결과 그렇게 차이가 나진 않았다.

