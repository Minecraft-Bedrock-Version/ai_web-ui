import boto3
import json
import os

from fastapi import Request, APIRouter

router = APIRouter()

lambda_client = boto3.client("lambda", region_name="ap-northeast-1")

@router.post("/lambda_invoke")
async def lambda_invoke(request: Request):
    try:
        data = await request.json()
        customCLI = data.get('customCLI', '입력된 명령어가 없습니다.')

        print(f"--- 람다 호출 로그 ---")
        print(f"사용자 CLI: {customCLI}")
        print(f"---------------------")

        payload = {
            "cli_input": customCLI,
            "account_id": "288528695623",
            "region": "us-east-1"
        }

        response = lambda_client.invoke(
            FunctionName="mbv_Graph_Lambda",
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )

        lambda_result = json.loads(response["Payload"].read())
        #body = lambda_result.get("body",{})
        #if isinstance(body, str):
        #   body = json.loads(body)
        

        #body = lambda_result.get("body", {})
        body = lambda_result
        
        if isinstance(body, str):
            body = json.loads(body)

        target_path = "/home/ubuntu/ai_web-ui/backend/json/pandyo/search_pandyo.json"
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(body, f, ensure_ascii=False, indent=2)

        return {
            "status": "success",
            "message": "백엔드 수신 완료",
            "received_cli": customCLI
        }
    except Exception as e:
        print(f"에러 발생: {str(e)}")
        return {"status": "error", "message": "데이터 형식이 올바르지 않습니다."}
