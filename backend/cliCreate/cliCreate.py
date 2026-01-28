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

    response = {
        "message": "CLI 생성완료",
        #여기에 실제 CLI 반환
        "cli": "cli입니다...",
        "state_echo": state
    }
    # cli 생성 로직

    return response