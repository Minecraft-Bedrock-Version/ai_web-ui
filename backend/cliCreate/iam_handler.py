"""
IAM 핸들러

IAM(ID 및 액세스 관리) 리소스(사용자, 역할, 그룹)에 대한 AWS CLI 명령어를 생성합니다.
action 필드를 기반으로 4가지 기능을 지원합니다:
  - inline_policy: 리소스 생성 + 인라인 정책 부여 (기존 goNext 방식)
  - create:        리소스 생성 + 관리형 정책 연결
  - attach_policy:  기존 리소스에 관리형 정책 연결
  - add_user_to_group: 그룹에 사용자 추가
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
                - action: 액션 종류 ("inline_policy", "create", "attach_policy", "add_user_to_group")
                - resource: 리소스 타입 ("user", "role", "group")
                - selectedEntity: 리소스 이름
                - activePolicies: 정책 데이터 (dict 또는 list)
            region: AWS 리전 (IAM은 글로벌 서비스이므로 사용하지 않음)
        
        Returns:
            str: 생성된 AWS CLI 명령어
        """
        action = state.get("action", "inline_policy")
        resource_type = state.get("resource", "")
        entity_name = state.get("selectedEntity", "")
        policies = state.get("activePolicies", {})
        
        # action에 따라 분기
        if action == "create":
            return self._handle_create(resource_type, entity_name, policies)
        elif action == "attach_policy":
            return self._handle_attach_policy(resource_type, entity_name, policies)
        elif action == "add_user_to_group":
            return self._handle_add_user_to_group(entity_name, policies)
        else:
            # 기본값: 인라인 정책 방식 (기존 goNext에서 오는 데이터)
            return self._handle_inline_policy(resource_type, entity_name, policies)
    
    # ─────────────────────────────────────────────
    # 1. 인라인 정책 (기존 goNext 방식)
    # ─────────────────────────────────────────────
    def _handle_inline_policy(self, resource_type: str, entity_name: str, active_policies: dict) -> str:
        """
        리소스 생성 + 인라인 정책 부여 CLI를 생성합니다.
        (기존 goNext() 함수에서 오는 데이터를 처리합니다.)
        
        active_policies 형식: { "s3": ["GetObject"], "ec2": ["StartInstances"] }
        """
        commands = []
        
        # 1. 리소스 생성 명령어
        create_cmd = self._create_resource_command(resource_type, entity_name)
        if create_cmd:
            commands.append(create_cmd)
        
        # 2. 인라인 정책 부여 (선택된 정책이 있는 경우에만)
        if active_policies:
            policy_json = self._generate_policy_json(active_policies)
            policy_str = json.dumps(policy_json, indent=2)
            
            if resource_type == "user":
                commands.append(f"aws iam put-user-policy --user-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'")
            elif resource_type == "role":
                commands.append(f"aws iam put-role-policy --role-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'")
            elif resource_type == "group":
                commands.append(f"aws iam put-group-policy --group-name {entity_name} --policy-name GeneratedPolicy --policy-document '{policy_str}'")
        
        return "\n".join(commands)
    
    # ─────────────────────────────────────────────
    # 2. 리소스 생성 + 관리형 정책 연결
    # ─────────────────────────────────────────────
    def _handle_create(self, resource_type: str, entity_name: str, policies: list) -> str:
        """
        리소스 생성 + 관리형 정책(ARN 또는 이름) 연결 CLI를 생성합니다.
        (submitCreateResource() 함수에서 오는 데이터를 처리합니다.)
        
        policies 형식: ["s3FullAccess", "ec2FullAccess"] 또는 ["arn:aws:iam::aws:policy/..."]
        """
        commands = []
        
        # 1. 리소스 생성
        create_cmd = self._create_resource_command(resource_type, entity_name)
        if create_cmd:
            commands.append(create_cmd)
        
        # 2. 관리형 정책 연결
        if policies and isinstance(policies, list):
            for policy in policies:
                attach_cmd = self._attach_policy_command(resource_type, entity_name, policy)
                if attach_cmd:
                    commands.append(attach_cmd)
        
        return "\n".join(commands)
    
    # ─────────────────────────────────────────────
    # 3. 기존 리소스에 관리형 정책만 연결
    # ─────────────────────────────────────────────
    def _handle_attach_policy(self, resource_type: str, entity_name: str, policies: list) -> str:
        """
        기존 리소스에 관리형 정책(ARN) 연결 CLI를 생성합니다.
        (submitAttachManagedPolicies() 함수에서 오는 데이터를 처리합니다.)
        리소스를 생성하지 않고 정책만 연결합니다.
        
        policies 형식: ["arn:aws:iam::aws:policy/AmazonS3FullAccess", ...]
        """
        commands = []
        
        if policies and isinstance(policies, list):
            for policy_arn in policies:
                attach_cmd = self._attach_policy_command(resource_type, entity_name, policy_arn)
                if attach_cmd:
                    commands.append(attach_cmd)
        
        return "\n".join(commands)
    
    # ─────────────────────────────────────────────
    # 4. 그룹에 사용자 추가
    # ─────────────────────────────────────────────
    def _handle_add_user_to_group(self, group_name: str, users: list) -> str:
        """
        그룹에 사용자를 추가하는 CLI를 생성합니다.
        (submitAddUsersToGroup() 함수에서 오는 데이터를 처리합니다.)
        
        group_name: 그룹 이름 (selectedEntity에서 가져옴)
        users: 추가할 사용자 이름 목록 (activePolicies에서 가져옴)
        """
        commands = []
        
        if users and isinstance(users, list):
            for user_name in users:
                commands.append(
                    f"aws iam add-user-to-group --group-name {group_name} --user-name {user_name}"
                )
        
        return "\n".join(commands)
    
    # ─────────────────────────────────────────────
    # 공통 헬퍼 메서드
    # ─────────────────────────────────────────────
    def _create_resource_command(self, resource_type: str, entity_name: str) -> str:
        """리소스 타입에 따른 생성 명령어를 반환합니다."""
        if resource_type == "user":
            return f"aws iam create-user --user-name {entity_name}"
        
        elif resource_type == "role":
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
            return f"aws iam create-role --role-name {entity_name} --assume-role-policy-document '{trust_policy_str}'"
        
        elif resource_type == "group":
            return f"aws iam create-group --group-name {entity_name}"
        
        return ""
    
    def _attach_policy_command(self, resource_type: str, entity_name: str, policy: str) -> str:
        """리소스 타입에 따른 관리형 정책 연결 명령어를 반환합니다."""
        # ARN이 아닌 경우 (예: "s3FullAccess") → 풀 ARN으로 변환
        if not policy.startswith("arn:"):
            policy_arn = f"arn:aws:iam::aws:policy/{policy}"
        else:
            policy_arn = policy
        
        if resource_type == "user":
            return f"aws iam attach-user-policy --user-name {entity_name} --policy-arn {policy_arn}"
        elif resource_type == "role":
            return f"aws iam attach-role-policy --role-name {entity_name} --policy-arn {policy_arn}"
        elif resource_type == "group":
            return f"aws iam attach-group-policy --group-name {entity_name} --policy-arn {policy_arn}"
        
        return ""
    
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
