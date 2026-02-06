"""
IAM 핸들러

IAM(ID 및 액세스 관리) 리소스(사용자, 역할, 그룹)에 대한 AWS CLI 명령어를 생성합니다.
"""

import json
from .base_handler import BaseHandler


class IAMHandler(BaseHandler):
    """IAM 관련 AWS CLI 명령어를 생성하는 핸들러입니다."""
    
    @property
    def service_name(self) -> str:
        return "iam"
    
    def generate_commands(self, state: dict, region: str = None) -> str:
        """
        IAM 리소스를 위한 AWS CLI 명령어를 생성합니다.
        
        Args:
            state: IAM 구성 정보
                - resource: 리소스 타입 ("user", "role", "group")
                - selectedEntity: 리소스 이름
                - activePolicies: 서비스별 허용할 액션 목록
            region: AWS 리전 (IAM은 글로벌 서비스이므로 사용하지 않음)
        
        Returns:
            str: 생성된 AWS CLI 명령어
        """
        resource_type = state.get("resource", "")
        entity_name = state.get("selectedEntity", "")
        active_policies = state.get("activePolicies", {})
        
        commands = []
        
        # 1. 기본 리소스 생성 명령어
        if resource_type == "user":
            # IAM 사용자(User) 생성
            create_cmd = f"aws iam create-user --user-name {entity_name}"
            commands.append(create_cmd)
            
        elif resource_type == "role":
            # IAM 역할(Role) 생성
            # EC2 서비스와 Lambda 서비스가 이 역할을 사용할 수 있도록 신뢰 정책을 설정합니다.
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
            # 윈도우 파워쉘 호환성을 위해 바깥은 작은따옴표('), 안쪽은 큰따옴표(")를 사용합니다.
            create_cmd = f"aws iam create-role --role-name {entity_name} --assume-role-policy-document '{trust_policy_str}'"
            commands.append(create_cmd)
            
        elif resource_type == "group":
            # IAM 그룹(Group) 생성
            create_cmd = f"aws iam create-group --group-name {entity_name}"
            commands.append(create_cmd)
        
        # 2. 인라인 정책 부여 (선택된 정책이 있는 경우에만)
        if active_policies:
            # 정책 내용을 JSON으로 생성
            policy_json = self._generate_policy_json(active_policies)
            policy_str = json.dumps(policy_json, indent=2)
            
            # 리소스 타입에 따라 정책 부여 명령어가 다릅니다.
            if resource_type == "user":
                policy_cmd = f"aws iam put-user-policy --user-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'"
                commands.append(policy_cmd)
                
            elif resource_type == "role":
                policy_cmd = f"aws iam put-role-policy --role-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'"
                commands.append(policy_cmd)
                
            elif resource_type == "group":
                policy_cmd = f"aws iam put-group-policy --group-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'"
                commands.append(policy_cmd)
        
        # 3. 모든 명령어를 줄바꿈(\n)으로 연결하여 반환
        return "\n".join(commands)
    
    def _generate_policy_json(self, active_policies: dict) -> dict:
        """
        선택된 액션 목록을 AWS IAM Policy JSON 형식으로 변환합니다.
        
        Args:
            active_policies: 서비스별 액션 목록 딕셔너리
                            예: {"s3": ["GetObject"], "ec2": ["StartInstances"]}
        
        Returns:
            dict: IAM Policy JSON 객체
        """
        # 모든 서비스의 액션을 하나의 리스트로 합칩니다.
        actions = []
        for service, action_list in active_policies.items():
            for action in action_list:
                # "서비스명:액션" 형태로 변환 (예: s3:GetObject)
                actions.append(f"{service}:{action}")
        
        # IAM Policy 기본 구조
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",  # 허용
                    "Action": actions,  # 액션 목록
                    "Resource": "*"     # 모든 리소스에 대해
                }
            ]
        }
        
        return policy
