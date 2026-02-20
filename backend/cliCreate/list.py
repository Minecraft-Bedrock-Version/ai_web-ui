import boto3
from fastapi import APIRouter, Request

router = APIRouter()


# AWS IAM의 사용자, 역할, 그룹과 직접 연결된 정책 불러오기
@router.post("/iam_list")
async def get_detailed_inventory():
    iam = boto3.client('iam')
    inventory = {"user": [], "role": [], "group": []}

    try:
        # 1. Users 조회
        users_data = iam.list_users()
        for u in users_data.get('Users', []):
            name = u['UserName']
            # 관리형 정책
            attached = iam.list_attached_user_policies(UserName=name)
            managed_policies = [p['PolicyName'] for p in attached.get('AttachedPolicies', [])]
            # 인라인 정책 (추가)
            inline = iam.list_user_policies(UserName=name)
            inline_policies = inline.get('PolicyNames', [])

            inventory["user"].append({
                "name": name, 
                "managed_policies": managed_policies,
                "inline_policies": inline_policies
            })

        # 2. Roles 조회
        roles_data = iam.list_roles()
        for r in roles_data.get('Roles', []):
            name = r['RoleName']
            # 관리형 정책
            attached = iam.list_attached_role_policies(RoleName=name)
            managed_policies = [p['PolicyName'] for p in attached.get('AttachedPolicies', [])]
            # 인라인 정책 (추가)
            inline = iam.list_role_policies(RoleName=name)
            inline_policies = inline.get('PolicyNames', [])

            inventory["role"].append({
                "name": name, 
                "managed_policies": managed_policies,
                "inline_policies": inline_policies
            })

        # 3. Groups 조회
        groups_data = iam.list_groups()
        for g in groups_data.get('Groups', []):
            name = g['GroupName']
            # 관리형 정책
            attached = iam.list_attached_group_policies(GroupName=name)
            managed_policies = [p['PolicyName'] for p in attached.get('AttachedPolicies', [])]
            # 인라인 정책 (추가)
            inline = iam.list_group_policies(GroupName=name)
            inline_policies = inline.get('PolicyNames', [])
            
            # 멤버 조회
            try:
                g_resp = iam.get_group(GroupName=name)
                members = [u['UserName'] for u in g_resp.get('Users', [])]
            except Exception:
                members = []

            inventory["group"].append({
                "name": name, 
                "managed_policies": managed_policies,
                "inline_policies": inline_policies,
                "members": members
            })

        return inventory

    except Exception as e:
        print(f"!!! AWS Error: {str(e)}")
        return {"error": str(e), "user": [], "role": [], "group": []}
    


@router.post("/ec2_list")
async def ec2_list(request: Request):

    print("EC2리스트 호출")
    body = await request.json()
    region = body.get("region")
    


    # boto3 EC2 클라이언트 생성
    ec2_client = boto3.client('ec2', region_name=region)  # 필요 시 region 조정

    # 모든 인스턴스 정보 가져오기
    response = ec2_client.describe_instances()

    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instances.append({
                "id": instance.get("InstanceId"),
                "name": next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), "-"),
                "state": instance.get("State", {}).get("Name"),
                "type": instance.get("InstanceType"),
                "publicIp": instance.get("PublicIpAddress") or "-"
            })

    return {"instances": instances}