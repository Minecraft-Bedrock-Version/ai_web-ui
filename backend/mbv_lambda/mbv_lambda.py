import boto3
import json
import os

# httpx는 비동기 요청을 위해 사용
import httpx

# Request 임포트
from fastapi import Request 

# fastapi 라우터 설정
from fastapi import APIRouter
router = APIRouter()


@router.post("/lambda_invoke")
async def lambda_invoke(request: Request):
    try:
        data = await request.json()
        
        customCLI = data.get('customCLI', '입력된 명령어가 없습니다.')

        print(f"--- 람다 호출 로그 ---")
        print(f"사용자 CLI: {customCLI}")
        print(f"---------------------")

        return {
            "status": "success",
            "message": "백엔드 수신 완료",
            "received_cli": customCLI
        }
    except Exception as e:
        print(f"에러 발생: {str(e)}")
        return {"status": "error", "message": "데이터 형식이 올바르지 않습니다."}