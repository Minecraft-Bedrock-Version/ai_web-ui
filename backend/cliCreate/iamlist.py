import boto3
from fastapi import APIRouter

router = APIRouter()

# 전역이 아닌 함수 안에서 선언하여 세션을 확실히 잡습니다.
@router.post("/iam_list")
async def get_detailed_inventory():
    print("--- [IAM List API Start] ---")
    
    # IAM Client 생성
    iam = boto3.client('iam')
    inventory = {"user": [], "role": [], "group": []}

    try:
        # 1. Users 수집
        users_data = iam.list_users()
        inventory["user"] = [u['UserName'] for u in users_data.get('Users', [])]
        print(f"Users found: {len(inventory['user'])}")

        # 2. Roles 수집
        roles_data = iam.list_roles()
        inventory["role"] = [r['RoleName'] for r in roles_data.get('Roles', [])]
        print(f"Roles found: {len(inventory['role'])}")

        # 3. Groups 수집
        groups_data = iam.list_groups()
        inventory["group"] = [g['GroupName'] for g in groups_data.get('Groups', [])]
        print(f"Groups found: {len(inventory['group'])}")

        print(f"Final Inventory: {inventory}")
        return inventory

    except Exception as e:
        print(f"!!! AWS Boto3 Error: {str(e)}")
        return {"error": str(e), "user": [], "role": [], "group": []}