# CLI Handler Pattern - Extension Guide

## 📋 새 서비스 핸들러 추가 가이드

새로운 AWS 서비스를 추가하는 방법을 예제로 설명합니다.

---

## 🚀 기본 구조

### Step 1: 핸들러 파일 생성

`backend/cliCreate/` 폴더에 `{서비스명}_handler.py` 파일을 생성합니다:

```python
"""
S3 핸들러

S3 버킷 관련 AWS CLI 명령어를 생성합니다.
"""

from .base_handler import BaseHandler


class S3Handler(BaseHandler):
    """S3 관련 AWS CLI 명령어를 생성하는 핸들러입니다."""
    
    @property
    def service_name(self) -> str:
        return "s3"
    
    def generate_commands(self, state: dict, region: str = None) -> str:
        """
        S3 리소스를 위한 AWS CLI 명령어를 생성합니다.
        
        Args:
            state: S3 구성 정보
            region: AWS 리전 (예: "ap-northeast-2")
        
        Returns:
            str: 생성된 AWS CLI 명령어
        """
        resource_type = state.get("resource", "bucket")
        commands = []
        
        if resource_type == "bucket":
            bucket_name = state.get("bucketName", "my-bucket")
            
            cmd = f"aws s3api create-bucket --bucket {bucket_name}"
            
            # 리전 처리 (us-east-1 외 리전은 LocationConstraint 필수)
            if region and region != "us-east-1":
                cmd += f" --region {region}"
                cmd += f" --create-bucket-configuration LocationConstraint={region}"
            
            commands.append(cmd)
        
        return "\n".join(commands)
```

### Step 2: 완료! 🎉

**자동 등록됩니다!** 다른 파일을 수정할 필요가 없습니다.

- ✅ `handler_registry.py`가 자동으로 탐지
- ✅ `cliCreate.py` 수정 불필요
- ✅ 프론트엔드에서 `{"service": "s3", ...}` 전송 시 자동 작동

---

## 🌏 리전(Region) 처리 가이드

### 리전을 사용하는 서비스

EC2, S3, VPC 등 리전 기반 서비스는 `region` 파라미터를 활용합니다:

```python
def generate_commands(self, state: dict, region: str = None) -> str:
    cmd = "aws ec2 run-instances"
    
    # 리전 옵션 추가
    if region:
        cmd += f" --region {region}"
    
    # ... 나머지 옵션
    return cmd
```

### 글로벌 서비스

IAM, Route53 등 글로벌 서비스는 `region`을 받지만 사용하지 않습니다:

```python
def generate_commands(self, state: dict, region: str = None) -> str:
    # region 파라미터는 받지만 사용하지 않음
    cmd = f"aws iam create-user --user-name {name}"
    return cmd
```

---

## 🔧 SSM Parameter 사용법

EC2 등에서 리전별 최신 AMI를 자동으로 가져오려면 SSM Parameter를 사용합니다:

```python
# OS/버전/아키텍처별 SSM Parameter Path 매핑
SSM_PARAM_MAP = {
    "amazon-linux": {
        "2023": {
            "x86_64": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            "arm64": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
        }
    },
    "ubuntu": {
        "22.04": {
            "x86_64": "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
        }
    }
}

# CLI에서 사용
cmd = f"aws ec2 run-instances --image-id resolve:ssm:{ssm_path}"
```

### SSM 장점
- ✅ 리전마다 AMI ID를 하드코딩할 필요 없음
- ✅ 항상 최신 공식 AMI 사용
- ✅ AWS가 관리하므로 유지보수 불필요

---

## 📡 프론트엔드 연동

### 요청 형식

```javascript
// EC2 인스턴스 생성 요청
const payload = {
    state: {
        service: "ec2",           // 필수: 서비스 식별자
        name: "my-instance",
        os: "amazon-linux",
        osVersion: "2023",
        arch: "x86_64",
        instanceType: "t3.micro",
        publicIp: "true",
        keypair: "my-key",
        imds: "required",
        encrypted: "true"
    },
    region: "ap-northeast-1"      // 필수: 대상 리전
};

fetch('/cli_create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
});
```

### 응답 형식

```json
{
    "message": "CLI 생성완료",
    "cli": "aws ec2 run-instances --region ap-northeast-1 --image-id resolve:ssm:... --instance-type t3.micro ...",
    "state_echo": { ... },
    "service": "ec2",
    "region": "ap-northeast-1"
}
```

---

## 🧪 핸들러 테스트

```python
from backend.cliCreate.handler_registry import get_handler

# EC2 핸들러 테스트
handler = get_handler("ec2")

state = {
    "service": "ec2",
    "name": "test-instance",
    "os": "amazon-linux",
    "osVersion": "2023",
    "arch": "x86_64",
    "instanceType": "t3.micro"
}

commands = handler.generate_commands(state, region="ap-northeast-1")
print(commands)

# 출력:
# aws ec2 run-instances --region ap-northeast-1 \
#   --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
#   --instance-type t3.micro ...
```

---

## ✅ 체크리스트

새 핸들러를 만들 때 확인하세요:

- [ ] 파일명이 `*_handler.py` 패턴인가?
- [ ] `BaseHandler`를 상속받았는가?
- [ ] `service_name` 프로퍼티를 구현했는가?
- [ ] `generate_commands(self, state: dict, region: str = None)` 시그니처를 따르는가?
- [ ] 리전 기반 서비스라면 `--region` 옵션을 추가했는가?

---

## 📊 지원 서비스 현황

| 서비스 | 파일 | 리전 사용 | 상태 |
|--------|------|----------|------|
| IAM | `iam_handler.py` | ❌ 글로벌 | ✅ 완료 |
| EC2 | `ec2_handler.py` | ✅ 사용 | ✅ 완료 |
| S3 | - | ✅ 사용 | 🔜 예정 |
| VPC | - | ✅ 사용 | 🔜 예정 |
