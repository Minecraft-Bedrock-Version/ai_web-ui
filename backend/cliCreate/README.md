# CLI 생성 모듈 구조 설명

## 📁 디렉토리 구조

```
backend/cliCreate/
├── router.py              # 통합 라우터 (main.py가 이것만 import)
├── cliCreate.py           # CLI 생성 API 엔드포인트
├── iamlist.py            # IAM 목록 API 엔드포인트
├── base_handler.py       # 모든 핸들러가 따라야 할 기본 틀
├── iam_handler.py        # IAM CLI 명령어 생성 담당
├── handler_registry.py   # 핸들러 자동 검색 및 등록 시스템
└── README_EXTEND.md      # 새 서비스 추가 가이드
```

---

## 🎯 각 파일의 역할

### 1. `router.py` (통합 라우터)
**역할**: 이 폴더의 모든 API를 하나로 모아서 main.py에 제공합니다.

**왜 만들었나요?**
- 앞으로 EC2, S3 등 서비스가 늘어날 때 main.py가 복잡해지는 걸 방지
- 한 줄로 모든 CLI 관련 API를 등록 가능

**사용 예시**:
```python
# main.py에서
from backend.cliCreate.router import router as cli_router
app.include_router(cli_router)  # 끝!
```

---

### 2. `cliCreate.py` (API 엔드포인트)
**역할**: 프론트엔드 요청을 받아서 적절한 핸들러에게 전달합니다.

**동작 방식**:
1. 프론트엔드에서 `POST /cli_create` 요청이 들어옴
2. `state` 데이터에서 서비스 종류 확인 (`service: "iam"`)
3. 해당 서비스 핸들러를 handler_registry에서 가져옴
4. 핸들러가 CLI 명령어를 만들어서 반환

**코드 흐름**:
```python
요청 → cliCreate.py → handler_registry → iam_handler → CLI 명령어 반환
```

---

### 3. `base_handler.py` (기본 틀)
**역할**: 모든 서비스 핸들러가 지켜야 할 "규칙"을 정의합니다.

**핵심 규칙**:
- 모든 핸들러는 `service_name` 속성을 가져야 함 (예: "iam")
- 모든 핸들러는 `generate_commands()` 함수를 구현해야 함

**비유**: 건물을 지을 때의 "건축 기준법"과 같습니다.

---

### 4. `iam_handler.py` (IAM 전문가)
**역할**: IAM 관련 AWS CLI 명령어를 생성합니다.

**할 수 있는 일**:
- IAM User 생성 명령어 만들기
- IAM Role 생성 명령어 만들기 (신뢰 정책 포함)
- IAM Group 생성 명령어 만들기
- 정책(Policy) 부여 명령어 만들기

**예시**:
```python
state = {
    "resource": "user",
    "selectedEntity": "john",
    "activePolicies": {"s3": ["GetObject"]}
}

# 결과:
# aws iam create-user --user-name john
# aws iam put-user-policy --user-name john --policy-name GeneratedPolicy ...
```

---

### 5. `handler_registry.py` (인사 담당자)
**역할**: 새로운 핸들러 파일이 추가되면 자동으로 찾아서 등록합니다.

**자동 검색 방식**:
1. `*_handler.py` 패턴의 파일을 모두 스캔
2. `BaseHandler`를 상속받은 클래스를 찾음
3. 자동으로 등록 (코드 수정 불필요!)

**장점**: EC2, S3 핸들러를 추가할 때 기존 코드를 전혀 건드리지 않아도 됨

---

## 🔄 전체 데이터 흐름

```
프론트엔드
    ↓
[POST /cli_create]
    ↓
router.py (라우팅)
    ↓
cliCreate.py (요청 처리)
    ↓
handler_registry (핸들러 찾기)
    ↓
iam_handler.py (명령어 생성)
    ↓
cliCreate.py (응답 반환)
    ↓
프론트엔드 (명령어 수신)
```

---

## ➕ 새 서비스 추가 방법

### 예: EC2 서비스 추가하기

**1단계**: `ec2_handler.py` 파일 생성
```python
from .base_handler import BaseHandler

class EC2Handler(BaseHandler):
    @property
    def service_name(self) -> str:
        return "ec2"
    
    def generate_commands(self, state: dict) -> str:
        # EC2 명령어 생성 로직
        return "aws ec2 run-instances ..."
```

**2단계**: 끝! 
- handler_registry가 자동으로 인식
- 프론트엔드에서 `{"service": "ec2", ...}` 보내면 바로 작동

---

## 🎓 팀원 설명용 한 줄 요약

> "예전엔 한 파일에 IAM 코드가 몰려있어서 나중에 EC2, S3 추가할 때 지저분해질 뻔했는데, 지금은 **각 서비스마다 담당 핸들러 파일을 만들면 자동으로 인식되는 구조**로 바꿨어요. 덕분에 코드 꼬일 걱정 없이 서비스를 무한정 추가할 수 있어요!"

---

## 📊 리팩토링 전후 비교

| 항목 | 리팩토링 전 | 리팩토링 후 |
|------|------------|------------|
| **IAM 코드 위치** | cliCreate.py (135줄) | iam_handler.py (독립) |
| **새 서비스 추가** | cliCreate.py 수정 필수 | 새 파일만 생성 |
| **main.py 복잡도** | 서비스마다 2줄씩 | 전체 1개 import |
| **코드 충돌 위험** | 높음 (한 파일 공유) | 낮음 (파일 분리) |
| **확장성** | 한계 있음 | 무제한 |

---

## ✅ 현재 지원 서비스

- **IAM**: User, Role, Group 생성 및 정책 부여

## 🚀 향후 추가 예정

- EC2: 인스턴스 생성, 보안 그룹 설정
- S3: 버킷 생성, 버전 관리 설정
- VPC: 네트워크 구성
- Lambda: 함수 생성 및 배포

---

## 📞 문의사항

새 서비스 추가나 기존 로직 수정이 필요하면 `README_EXTEND.md`를 참고하세요.
