# CLI 생성 모듈 구조 설명

## 📁 디렉토리 구조

```
backend/cliCreate/
├── router.py              # 통합 라우터 (main.py가 이것만 import)
├── cliCreate.py           # CLI 생성 API 엔드포인트
├── list.py                # 리소스 목록 API 엔드포인트
├── base_handler.py        # 모든 핸들러가 따라야 할 기본 틀
├── iam_handler.py         # IAM CLI 명령어 생성 담당
├── ec2_handler.py         # EC2 CLI 명령어 생성 담당
├── handler_registry.py    # 핸들러 자동 검색 및 등록 시스템
└── README_EXTEND.md       # 새 서비스 추가 가이드
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
2. `state` 데이터에서 서비스 종류 확인 (`service: "ec2"`)
3. `region` 데이터 추출 (프론트엔드에서 전송)
4. 해당 서비스 핸들러를 handler_registry에서 가져옴
5. 핸들러가 CLI 명령어를 만들어서 반환

**코드 흐름**:
```
요청 (state + region) → cliCreate.py → handler_registry → ec2_handler → CLI 명령어 반환
```

---

### 3. `base_handler.py` (기본 틀)
**역할**: 모든 서비스 핸들러가 지켜야 할 "규칙"을 정의합니다.

**핵심 규칙**:
- 모든 핸들러는 `service_name` 속성을 가져야 함 (예: "iam", "ec2")
- 모든 핸들러는 `generate_commands(state, region)` 함수를 구현해야 함

**메서드 시그니처**:
```python
def generate_commands(self, state: dict, region: str = None) -> str:
```

---

### 4. `iam_handler.py` (IAM 전문가)
**역할**: IAM 관련 AWS CLI 명령어를 생성합니다.

**할 수 있는 일**:
- IAM User 생성 명령어 만들기
- IAM Role 생성 명령어 만들기 (신뢰 정책 포함)
- IAM Group 생성 명령어 만들기
- 정책(Policy) 부여 명령어 만들기

> **참고**: IAM은 글로벌 서비스이므로 `region` 파라미터를 받지만 사용하지 않습니다.

---

### 5. `ec2_handler.py` (EC2 전문가) 🆕
**역할**: EC2 인스턴스 관련 AWS CLI 명령어를 생성합니다.

**핵심 기능**:
- **리전 자동 연동**: 프론트엔드에서 선택한 리전이 CLI에 `--region` 옵션으로 포함
- **SSM Parameter 사용**: 리전에 관계없이 최신 AMI ID를 자동으로 해결

**예시**:
```python
state = {
    "service": "ec2",
    "name": "my-instance",
    "os": "amazon-linux",
    "osVersion": "2023",
    "arch": "x86_64",
    "instanceType": "t3.micro"
}
region = "ap-northeast-1"  # 도쿄

# 결과:
# aws ec2 run-instances --region ap-northeast-1 \
#   --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
#   --instance-type t3.micro ...
```

---

### 6. `handler_registry.py` (인사 담당자)
**역할**: 새로운 핸들러 파일이 추가되면 자동으로 찾아서 등록합니다.

**자동 검색 방식**:
1. `*_handler.py` 패턴의 파일을 모두 스캔
2. `BaseHandler`를 상속받은 클래스를 찾음
3. 자동으로 등록 (코드 수정 불필요!)

---

## 🌏 리전 연동 시스템

### 데이터 흐름
```
프론트엔드 (region 선택)
    ↓
{state: {...}, region: "ap-northeast-1"}
    ↓
cliCreate.py (region 추출)
    ↓
handler.generate_commands(state, region)
    ↓
CLI: aws ec2 run-instances --region ap-northeast-1 ...
```

### 지원 리전
모든 AWS 리전을 지원합니다. 프론트엔드에서 전송한 리전 값이 그대로 CLI에 적용됩니다.

### SSM Parameter란?
각 리전에서 최신 공식 AMI ID를 자동으로 가져오는 AWS 서비스입니다.
```bash
# 예시: 도쿄 리전에서 실행하면 도쿄의 최신 AMI를 자동 사용
aws ec2 run-instances \
  --region ap-northeast-1 \
  --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
```

---

## 🔄 전체 데이터 흐름

```
프론트엔드
    ↓
[POST /cli_create] {state, region}
    ↓
router.py (라우팅)
    ↓
cliCreate.py (요청 처리 + region 추출)
    ↓
handler_registry (핸들러 찾기)
    ↓
ec2_handler.py (명령어 생성 + --region 추가)
    ↓
cliCreate.py (응답 반환)
    ↓
프론트엔드 (명령어 수신)
```

---

## ➕ 새 서비스 추가 방법

### 예: S3 서비스 추가하기

**1단계**: `s3_handler.py` 파일 생성
```python
from .base_handler import BaseHandler

class S3Handler(BaseHandler):
    @property
    def service_name(self) -> str:
        return "s3"
    
    def generate_commands(self, state: dict, region: str = None) -> str:
        bucket_name = state.get("bucketName", "my-bucket")
        
        cmd = f"aws s3api create-bucket --bucket {bucket_name}"
        if region and region != "us-east-1":
            cmd += f" --region {region}"
            cmd += f" --create-bucket-configuration LocationConstraint={region}"
        
        return cmd
```

**2단계**: 끝! 
- handler_registry가 자동으로 인식
- 프론트엔드에서 `{"service": "s3", ...}` 보내면 바로 작동

---

## ✅ 현재 지원 서비스

| 서비스 | 리전 사용 | 설명 |
|--------|----------|------|
| **IAM** | ❌ (글로벌) | User, Role, Group 생성 및 정책 부여 |
| **EC2** | ✅ | 인스턴스 생성 (SSM Parameter로 AMI 자동 해결) |

## 🚀 향후 추가 예정

- S3: 버킷 생성, 버전 관리 설정
- VPC: 네트워크 구성
- Lambda: 함수 생성 및 배포

---

## 📞 문의사항

새 서비스 추가나 기존 로직 수정이 필요하면 `README_EXTEND.md`를 참고하세요.
