import boto3
from fastapi import APIRouter

router = APIRouter()


@router.post("/iam_list")
async def get_detailed_inventory():
    iam = boto3.client('iam')
    inventory = {"user": [], "role": [], "group": []}

    try:
        # 1. Users + Policies
        users_data = iam.list_users()
        for u in users_data.get('Users', []):
            name = u['UserName']
            # 해당 유저에게 연결된 정책 조회
            p_resp = iam.list_attached_user_policies(UserName=name)
            policies = [p['PolicyName'] for p in p_resp.get('AttachedPolicies', [])]
            inventory["user"].append({"name": name, "policies": policies})

        # 2. Roles + Policies
        roles_data = iam.list_roles()
        for r in roles_data.get('Roles', []):
            name = r['RoleName']
            p_resp = iam.list_attached_role_policies(RoleName=name)
            policies = [p['PolicyName'] for p in p_resp.get('AttachedPolicies', [])]
            inventory["role"].append({"name": name, "policies": policies})

        # 3. Groups + Policies
        groups_data = iam.list_groups()
        for g in groups_data.get('Groups', []):
            name = g['GroupName']
            p_resp = iam.list_attached_group_policies(GroupName=name)
            policies = [p['PolicyName'] for p in p_resp.get('AttachedPolicies', [])]
            inventory["group"].append({"name": name, "policies": policies})

        return inventory

    except Exception as e:
        print(f"!!! AWS Error: {str(e)}")
        return {"error": str(e), "user": [], "role": [], "group": []}