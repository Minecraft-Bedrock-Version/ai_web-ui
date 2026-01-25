#박혜수 작업물
import boto3
import json
import requests 
import re

# 필요한 라이브러리 추가
import os
from dotenv import load_dotenv
from fastapi import Request
# fastapi 라우터 설정
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

load_dotenv()

router = APIRouter()

# 리전 설정 추가
lambda_client = boto3.client("lambda", region_name="ap-northeast-1")



OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")


class GrokRequest(BaseModel):
    grok_result: dict
    user_cli_input: str

#그록 실행 함수로 지정
@router.post("/grok_json")
def grok_json(request: Request):
    try:
        print("그록 실행합니다")

        data = request.json()
        user_cli_input = data.get('customCLI')
        # user_cli_input = """aws iam put-user-policy \
        # --user-name scp_test \
        # --policy-name cg-sqs-scenario-assumed-role \
        # --policy-document '{
        # "Version": "2012-10-17",
        # "Statement": [
        # {
        # "Effect": "Allow",
        # "Action": [
        #     "iam:Get*",
        #     "iam:List*"
        # ],
        # "Resource": "*"
        #     }
        # ]
        # }'"""
        print("사용자 입력 CLI(grok_json):", user_cli_input)
        if not user_cli_input:
            return {"error":"사용자 CLI 입력이 비어 있습니다."}

        system_prompt = """
        You are an AWS IAM least-privilege policy generator.

        Rules (MANDATORY):
        - Determine permissions required to EXECUTE the CLI command only.
        - NEVER analyze or reuse permissions inside --policy-document.
        - NEVER invent AWS actions.
        - Return the MINIMUM required IAM permissions.
        - Scope Resource as narrowly as possible.
        - Prefer specific ARN over "*".
        - Output ONLY valid IAM policy JSON.
        - No explanations. No markdown.
        """

        user_prompt = f"""
        AWS CLI command:
        {user_cli_input}

        Return the minimum IAM policy required to execute this command.
        """

        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            data=json.dumps({
                "model": "x-ai/grok-4.1-fast",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "reasoning": {"enabled": True}
        })
    )

        #응답에서 JSON 부분 추출
        result = response.json()
        print("Grok(json):",result)
        return {"message": "success","grok_result": result, "user_cli_input": user_cli_input}
    except Exception as e:
        print(f"오류발생:{e}")
        return {"message":"error","error":str(e)}


@router.post("/grok_exe")
def run_grok_exe(data: GrokRequest):
    result = data.grok_result
    user_cli_input = data.user_cli_input
    print("grok_result:",result)
    print("user_cli_input:",user_cli_input)
    try:
        print("JSON실행 실행")
        content = result["choices"][0]["message"]["content"]

        match = re.search(r'\{[\s\S]*\}', content)
        if not match:
            raise RuntimeError("No valid JSON policy returned from Grok")

        policy_document = json.loads(match.group(0))

        lambda_event = {
            "policy_name": "codebuild-assume-policy",
            "policy_document": policy_document,
            "cli_commands": user_cli_input
        }
        response = lambda_client.invoke(
            FunctionName="mbv_Codebuild_Lambda",
            InvocationType="RequestResponse",
            Payload=json.dumps(lambda_event)
        )

        lambda_result = json.loads(response["Payload"].read())
        print(lambda_result)

        return {"message": "success","lambda_result": lambda_result}
    except Exception as e:
        print(f"오류 발생:{e}")
        return {"message": "error", "error":str(e)}