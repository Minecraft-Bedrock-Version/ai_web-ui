#박혜수 작업물
import boto3
import json
import requests 
import re

# 필요한 라이브러리 추가
import os
from dotenv import load_dotenv
# fastapi 라우터 설정
from fastapi import APIRouter
router = APIRouter()

# 리전 설정 추가
lambda_client = boto3.client("lambda", region_name="ap-northeast-1")

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

#그록 실행 함수로 지정
@router.post("/grok_exe")
def run_grok_exe():
    try:
        print("그록 실행합니다")
        user_cli_input = """aws iam put-user-policy \
        --user-name scp_test \
        --policy-name cg-sqs-scenario-assumed-role \
        --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
        {
        "Effect": "Allow",
        "Action": [
            "iam:Get*",
            "iam:List*"
        ],
        "Resource": "*"
            }
        ]
        }'"""

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

        result = response.json()
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