import json
import boto3
import os  # 경로 처리를 위해 추가
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError

from fastapi import APIRouter, Request

router = APIRouter()

# --- 경로 설정 (이미지 구조 반영) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 1. 분석 대상 파일 (backend/json/pandyo/search_pandyo.json) - search_pandyo.py에서 인프라 받아오기(사용자 인프라)
TARGET_JSON_PATH = os.path.join(BASE_DIR, "..", "json", "pandyo", "search_pandyo.json")


'''
# 2. RAG용 지식 베이스 (backend/document/sqs_flag_shop.json) - mbv_search.py에서 경로 받아오기
CONTEXT_PATH = os.path.join(BASE_DIR, "..", "document", "sqs_flag_shop.json")
'''

def run_security_analysis(target_infra_json: str, retrieved_context: str) -> Optional[str]: # 리턴 타입을 str로 변경
    """
    EC2에서 지정된 모델을 사용하여 클라우드 보안 분석을 수행합니다.
    """
    # # 1. 취약점 지식 베이스(RAG) 파일 읽기
    # try:
    #     with open(CONTEXT_PATH, "r", encoding="utf-8") as f:
    #         retrieved_context = f.read()
    # except FileNotFoundError:
    #     print(f"Error: {CONTEXT_PATH} 파일을 찾을 수 없습니다.")
    #     return None


    # 2. 프롬프트 템플릿 정의
    # (주의: f-string 내의 중괄호는 {{ }}로 이중 처리해야 합니다.)
    prompt_template = f"""
# Role
너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
너의 목표는 단순한 설정 오류 나열이 아니라, 현실적인 공격자가 실제로 악용 가능한 권한 조합과 신뢰 경계 붕괴 시나리오를 논리적으로 증명하는 것이다.


---
# Context: 취약점 지식 베이스 (RAG)
{retrieved_context}

---
# Input: 분석 대상 인프라 구성 (JSON)
{target_infra_json}

---
# Guidelines for Deep Analysis
1. **[Effective Permission Calculation]**: Allow 뿐만 아니라 Deny, SCP, Permissions Boundary 등을 모두 대조하여 실제 유효 권한을 계산하라.
2. **[Identity vs Resource-based Policy Interaction]**: IAM 정책과 리소스 기반 정책의 상호작용을 분석하여 신뢰 경계 붕괴를 식별하라.
3. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로를 시뮬레이션하라.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.


# Output Format
분석 결과는 마크다운 기호(#, *, -, | 등)를 전혀 사용하지 않은 순수 텍스트(Plain Text)의 보고서 형식으로 작성하라.
취약점의 심각도, 공격 시나리오, 대응 방안을 포함해야 한다.

# Language Setting (중요)
반드시 모든 내용은 한국어로 작성하라. 전문 용어는 괄호 안에 영문을 병기할 수 있다.
"""

    # 3. Bedrock/LLM 클라이언트 및 페이로드 설정
    client = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
    model_id = 'openai.gpt-oss-120b-1:0'

    # f-string 중괄호 오류 방지를 위해 딕셔너리 먼저 생성 후 json.dumps
    payload = {
        "messages": [
   {
                "role": "system",
                "content": "너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다."
            },
            {
                "role": "user",
                "content": prompt_template  # 기존에 정의한 prompt_template을 여기에 넣습니다.
            }
        ],
        "max_tokens": 2096,
        "temperature": 0.2,
        "top_p": 0.9,
        "reasoning_effort": "medium"
    }
    body = json.dumps(payload)

    try:
        response = client.invoke_model(
            body=body,
            modelId=model_id,
            accept='application/json',
            contentType='application/json'
        )
        response_body = json.loads(response.get('body').read())
# 모델 응답 구조에 따라 텍스트 추출 (choices 또는 completion)
        if 'choices' in response_body:
            result_text = response_body['choices'][0]['message']['content']
        else:
            result_text = response_body.get('completion', "")
        
        # ⭐ 핵심 수정: json.loads()를 절대 하지 말고 텍스트 그대로 리턴합니다.
        return result_text.strip() 

    except Exception as e:
        print(f"오류 발생: {e}")
        return None
    
def resolve_doc_path(relative_path: str) -> str:
    """
    mbv_search에서 받은 경로를
    프로젝트 기준 절대경로로 변환
    """
    return os.path.abspath(
        os.path.join(BASE_DIR, "..", relative_path.lstrip("/"))
    )

def run_mbv_llm(description: str) -> str:

# 사용자 인프라 읽기
    if not os.path.exists(TARGET_JSON_PATH):
        raise FileNotFoundError(f"분석 대상 파일 없음:{TARGET_JSON_PATH}")
    with open(TARGET_JSON_PATH, "r", encoding='utf-8') as f:
        target_infra_json = json.dumps(json.load(f), ensure_ascii=False)


# RAG 문서 읽기

    # description == "document/sqs_flag_shop.json"
    doc_path = resolve_doc_path(description)

    if not os.path.exists(doc_path):
        raise FileNotFoundError(f"문서 없음: {doc_path}")

    with open(doc_path, "r", encoding="utf-8") as f:
        retrieved_context = f.read()

 # LLM 분석 실행
    analysis_result = run_security_analysis(target_infra_json, retrieved_context)

    return analysis_result

# --- 실행부 수정 ---
# 외부에서 호출 계획 없으면 필요x
@router.post("/mbv_llm_gpt")
async def mbv_llm_gpt(request: Request):
    print("mbv_llm_gpt 함수 실행됨")
    body = await request.json()
    description = body.get("descritpion")
    print("llm에 전돨된 descritpion:", description)
    analysis_result = run_mbv_llm(description)
    return {"analysis_result": analysis_result}

    '''
    return{"message": "mbv_llm_gpt 호출"}
'''
'''
    # 1. search_pandyo.json 파일 읽기
    try:
        if not os.path.exists(TARGET_JSON_PATH):
            print(f"❌ 분석 대상 파일을 찾을 수 없습니다: {TARGET_JSON_PATH}")
        else:
            with open(TARGET_JSON_PATH, "r", encoding="utf-8") as f:
                # 파일 전체를 읽어서 문자열로 변환
                search_pandyo_data = json.load(f)
                target_infra_json_str = json.dumps(search_pandyo_data, indent=2, ensure_ascii=False)
            
            print(f"🚀 {TARGET_JSON_PATH} 파일을 기반으로 분석을 시작합니다...")
            
            # 2. 분석 실행
            analysis_result = run_security_analysis(target_infra_json_str)
            
            if analysis_result:
                print("\n✅ 분석 완료:")
                print(json.dumps(analysis_result, indent=4, ensure_ascii=False))
            
            # 임시 리턴값
            return 1 
    except Exception as e:
        print(f"❌ 실행 중 오류 발생: {e}")
        return e
'''