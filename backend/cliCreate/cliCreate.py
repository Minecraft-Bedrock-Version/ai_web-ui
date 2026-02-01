import boto3
import json
import os

# Request 임포트
from fastapi import Request 

# fastapi 라우터 설정
from fastapi import APIRouter
router = APIRouter()

@router.post("/cli_create")
async def cli_create(request: Request):
    data = await request.json()
    print("cli_create 함수 실행됨")
    print("받은 데이터:", data)

    state = data.get("state")
    print("받은 state:", state)

    # CLI 명령어 생성 로직
    cli_commands = generate_cli_commands(state)
    
    response = {
        "message": "CLI 생성완료",
        "cli": cli_commands,
        "state_echo": state
    }

    return response


def generate_policy_json(active_policies: dict) -> dict:
    """
    activePolicies 딕셔너리를 AWS IAM Policy JSON 구조로 변환합니다.
    
    Args:
        active_policies: 서비스별 액션 목록 딕셔너리
                        예: {"s3": ["GetObject", "PutObject"], "ec2": ["StartInstances"]}
    
    Returns:
        IAM Policy JSON (딕셔너리 형태)
    """
    # 모든 서비스의 액션을 하나의 리스트로 결합
    actions = []
    for service, action_list in active_policies.items():
        for action in action_list:
            # "서비스명:액션" 형태로 변환
            actions.append(f"{service}:{action}")
    
    # IAM Policy JSON 구조 생성
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*"
            }
        ]
    }
    
    return policy


def generate_cli_commands(state: dict) -> str:
    """
    state 객체를 기반으로 AWS CLI 명령어 스크립트를 생성합니다.
    
    Args:
        state: 프론트엔드에서 전달된 IAM 구성 정보
               - resource: 리소스 타입 ("user", "role", "group")
               - selectedEntity: 리소스 이름
               - activePolicies: 서비스별 액션 목록 딕셔너리
    
    Returns:
        생성된 AWS CLI 명령어 스크립트 (문자열)
    """
    resource_type = state.get("resource", "")
    entity_name = state.get("selectedEntity", "")
    active_policies = state.get("activePolicies", {})
    
    commands = []
    
    # 1. 기본 리소스 생성 명령어
    if resource_type == "user":
        # IAM User 생성
        create_cmd = f"aws iam create-user --user-name {entity_name}"
        commands.append(create_cmd)
        
    elif resource_type == "role":
        # IAM Role 생성 (EC2와 Lambda가 assume 할 수 있는 기본 신뢰 정책)
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        trust_policy_str = json.dumps(trust_policy, indent=2)
        # Windows PowerShell에서는 작은따옴표로 감싸고, JSON 내부는 큰따옴표 유지
        create_cmd = f"aws iam create-role --role-name {entity_name} --assume-role-policy-document '{trust_policy_str}'"
        commands.append(create_cmd)
        
    elif resource_type == "group":
        # IAM Group 생성
        create_cmd = f"aws iam create-group --group-name {entity_name}"
        commands.append(create_cmd)
    
    # 2. 인라인 정책 부여 (activePolicies가 있는 경우에만)
    if active_policies:
        # Policy JSON 생성
        policy_json = generate_policy_json(active_policies)
        policy_str = json.dumps(policy_json, indent=2)
        
        # 리소스 타입에 따라 적절한 정책 부여 명령어 생성
        if resource_type == "user":
            policy_cmd = f"aws iam put-user-policy --user-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'"
            commands.append(policy_cmd)
            
        elif resource_type == "role":
            policy_cmd = f"aws iam put-role-policy --role-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'"
            commands.append(policy_cmd)
            
        elif resource_type == "group":
            policy_cmd = f"aws iam put-group-policy --group-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'"
            commands.append(policy_cmd)
    
    # 3. 모든 명령어를 줄바꿈으로 연결하여 반환
    return "\n".join(commands)