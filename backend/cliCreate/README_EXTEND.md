# CLI Handler Pattern - Future Extension Example

## Adding a New Service (e.g., EC2)

새로운 AWS 서비스를 추가하는 방법을 예제로 설명합니다.

### Step 1: Create New Handler File

`handlers/ec2_handler.py` 파일을 생성합니다:

```python
"""
EC2 Handler

Generates AWS CLI commands for EC2 resources.
"""

import json
from .base_handler import BaseHandler


class EC2Handler(BaseHandler):
    """Handler for generating EC2-related AWS CLI commands."""
    
    @property
    def service_name(self) -> str:
        return "ec2"
    
    def generate_commands(self, state: dict) -> str:
        """
        Generate AWS CLI commands for EC2 resources.
        
        Args:
            state: EC2 configuration state
                - resource: Resource type ("instance", "security-group", "key-pair")
                - instanceType: EC2 instance type (e.g., "t2.micro")
                - amiId: AMI ID
                - keyName: Key pair name
                - securityGroups: List of security group IDs
        
        Returns:
            str: AWS CLI commands (newline-separated)
        """
        resource_type = state.get("resource", "")
        commands = []
        
        if resource_type == "instance":
            # EC2 Instance 생성
            instance_type = state.get("instanceType", "t2.micro")
            ami_id = state.get("amiId", "ami-0c55b159cbfafe1f0")
            key_name = state.get("keyName", "")
            
            cmd = f"aws ec2 run-instances --image-id {ami_id} --instance-type {instance_type}"
            
            if key_name:
                cmd += f" --key-name {key_name}"
            
            commands.append(cmd)
            
        elif resource_type == "security-group":
            # Security Group 생성
            group_name = state.get("groupName", "")
            description = state.get("description", "Created by CLI generator")
            
            cmd = f"aws ec2 create-security-group --group-name {group_name} --description '{description}'"
            commands.append(cmd)
            
        elif resource_type == "key-pair":
            # Key Pair 생성
            key_name = state.get("keyName", "")
            
            cmd = f"aws ec2 create-key-pair --key-name {key_name} --query 'KeyMaterial' --output text > {key_name}.pem"
            commands.append(cmd)
        
        return "\n".join(commands)
```

### Step 2: That's It! 🎉

**자동 등록됩니다!** 다른 파일을 수정할 필요가 없습니다.

- ✅ `handler_registry.py`가 자동으로 탐지
- ✅ `cliCreate.py` 수정 불필요
- ✅ 프론트엔드에서 `{"service": "ec2", ...}` 전송 시 자동 작동

### Step 3: Test the New Handler

```python
from handler_registry import get_handler

handler = get_handler("ec2")

state = {
    "resource": "instance",
    "instanceType": "t2.micro",
    "amiId": "ami-0c55b159cbfafe1f0",
    "keyName": "my-key"
}

commands = handler.generate_commands(state)
print(commands)
# Output: aws ec2 run-instances --image-id ami-0c55b159cbfafe1f0 --instance-type t2.micro --key-name my-key
```

---

## Adding S3 Handler Example

`handlers/s3_handler.py`:

```python
from .base_handler import BaseHandler


class S3Handler(BaseHandler):
    @property
    def service_name(self) -> str:
        return "s3"
    
    def generate_commands(self, state: dict) -> str:
        resource_type = state.get("resource", "")
        commands = []
        
        if resource_type == "bucket":
            bucket_name = state.get("bucketName", "")
            region = state.get("region", "us-east-1")
            
            # 버킷 생성
            if region == "us-east-1":
                cmd = f"aws s3api create-bucket --bucket {bucket_name}"
            else:
                cmd = f"aws s3api create-bucket --bucket {bucket_name} --region {region} --create-bucket-configuration LocationConstraint={region}"
            
            commands.append(cmd)
            
            # 버전 관리 활성화
            if state.get("enableVersioning", False):
                cmd = f"aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled"
                commands.append(cmd)
        
        return "\n".join(commands)
```

---

## Frontend Integration

프론트엔드에서 `service` 필드를 추가하여 사용:

```javascript
// IAM 요청 (기존 방식 - 여전히 작동)
const iamRequest = {
    state: {
        // service 필드 없으면 자동으로 "iam"
        resource: "user",
        selectedEntity: "my-user",
        activePolicies: { s3: ["GetObject"] }
    }
};

// EC2 요청 (새로운 방식)
const ec2Request = {
    state: {
        service: "ec2",  // 추가!
        resource: "instance",
        instanceType: "t2.micro",
        amiId: "ami-xxx",
        keyName: "my-key"
    }
};

// S3 요청 (새로운 방식)
const s3Request = {
    state: {
        service: "s3",  // 추가!
        resource: "bucket",
        bucketName: "my-bucket",
        region: "ap-northeast-2",
        enableVersioning: true
    }
};
```

---

## Benefits of This Pattern

✅ **확장성**: 새 서비스 추가 시 새 파일만 생성  
✅ **유지보수**: 각 서비스 로직이 독립적  
✅ **자동 등록**: 수동 등록 불필요  
✅ **테스트**: 핸들러별 독립 테스트 가능  
✅ **하위 호환**: 기존 IAM 요청 여전히 작동
