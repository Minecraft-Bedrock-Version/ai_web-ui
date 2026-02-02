import boto3
from fastapi import APIRouter

router = APIRouter()


# AWS IAM의 사용자, 역할, 그룹과 직접 연결된 정책 불러오기
@router.post("/iam_list")
async def get_detailed_inventory():
    # IAM 서비스 클라이언트 초기화
    iam = boto3.client('iam')

    # 결과 데이터 구조 초기화
    inventory = {"user": [], "role": [], "group": []}

    try:
        # 1. Users + Policies 조회
        users_data = iam.list_users()
        for u in users_data.get('Users', []):
            name = u['UserName']
            # 해당 유저에게 연결된 '관리형 정책' 조회
            p_resp = iam.list_attached_user_policies(UserName=name)
            policies = [p['PolicyName'] for p in p_resp.get('AttachedPolicies', [])]

            # 사용자 이름과 정책 리트 저장
            inventory["user"].append({"name": name, "policies": policies})

        # 2. Roles + Policies 조회
        roles_data = iam.list_roles()
        for r in roles_data.get('Roles', []):
            name = r['RoleName']
            p_resp = iam.list_attached_role_policies(RoleName=name)
            policies = [p['PolicyName'] for p in p_resp.get('AttachedPolicies', [])]
            inventory["role"].append({"name": name, "policies": policies})

        # 3. Groups + Policies 조회
        groups_data = iam.list_groups()
        for g in groups_data.get('Groups', []):
            name = g['GroupName']
            p_resp = iam.list_attached_group_policies(GroupName=name)
            policies = [p['PolicyName'] for p in p_resp.get('AttachedPolicies', [])]
            inventory["group"].append({"name": name, "policies": policies})

        # 결과 데이터 반환
        return inventory

    except Exception as e:
        print(f"!!! AWS Error: {str(e)}")
        return {"error": str(e), "user": [], "role": [], "group": []}