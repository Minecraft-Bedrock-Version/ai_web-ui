# 양유상 작업물
import json
import boto3
import os  # 경로 처리를 위해 추가
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError

from fastapi import APIRouter, Request

import re

router = APIRouter()

# --- 경로 설정 (이미지 구조 반영) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 1. 분석 대상 파일 (backend/json/pandyo/search_pandyo.json) - search_pandyo.py에서 인프라 받아오기(사용자 인프라)
TARGET_JSON_PATH = os.path.join(BASE_DIR, "..", "json", "pandyo", "search_pandyo.json")


'''
# 2. RAG용 지식 베이스 (backend/document/sqs_flag_shop.json) - mbv_search.py에서 경로 받아오기
CONTEXT_PATH = os.path.join(BASE_DIR, "..", "document", "sqs_flag_shop.json")
'''

def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """
    모델 출력에서 <reasoning> 태그를 제거하고 순수 JSON 객체만 추출한다.
    """
    if not text:
        return None

    # 1. <reasoning> 태그 및 내부 내용 전체 제거 (가장 중요)
    clean_text = re.sub(r'<reasoning>.*?</reasoning>', '', text, flags=re.DOTALL).strip()

    # 2. JSON 객체 찾기 ({ } 추출)
    start = clean_text.find("{")
    end = clean_text.rfind("}")
    
    if start != -1 and end != -1 and end > start:
        json_str = clean_text[start:end + 1]
        try:
            parsed = json.loads(json_str)
            if isinstance(parsed, dict):
                # 만약 모델이 summary 계산을 못했다면 기본값이라도 채워줌
                if "vulnerabilities" in parsed and "summary" not in parsed:
                    v = parsed["vulnerabilities"]
                    parsed["summary"] = {
                        "high": len([x for x in v if x.get("severity") == "high"]),
                        "medium": len([x for x in v if x.get("severity") == "medium"]),
                        "low": len([x for x in v if x.get("severity") == "low"]),
                    }
                return parsed
        except json.JSONDecodeError as e:
            print(f"JSON 추출 후 파싱 실패: {e}")
            return None

    return None


def run_security_analysis(target_infra_json: str, retrieved_context: str) -> Optional[Dict[str, Any]]:
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
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 단순한 설정 오류 나열이 아니라, 현실적인 공격자가 실제로 악용 가능한 권한 조합과 신뢰 경계 붕괴 시나리오를 논리적으로 증명한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{target_infra_json}

[분석 실행 전략 (반드시 준수)]
1. **Primary Task (RAG 시나리오 검증):**
   - 최우선적으로 상기 '컨텍스트'에 명시된 공격 기법이 '입력된 인프라'에서 실제로 재현 가능한지 검증하라.
   - 해당 시나리오가 성립한다면 이를 결과에 반드시 포함해야 한다.

2. **Secondary Task (Zero-Base 확장 탐지):**
   - RAG 시나리오 검증 후 분석을 멈추지 말고, 네가 가진 클라우드 보안 지식(OWASP, AWS Best Practices)을 총동원하여 인프라 전체를 다시 스캔하라.
   - 컨텍스트에 없는 치명적인 취약점(IAM 권한 오남용, 리소스 노출, 암호화 미비 등)을 식별하여 보고하라.

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow 뿐만 아니라 Deny, SCP, Permissions Boundary 등을 모두 대조하여 실제 유효 권한을 계산하라.
2. **[Identity vs Resource-based Policy Interaction]**: IAM 정책과 리소스 기반 정책의 상호작용을 분석하여 신뢰 경계 붕괴를 식별하라.
3. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로를 시뮬레이션하라.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.


출력 형식
아래 스키마의 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{
    "summary": {{ "high": 0, "medium": 0, "low": 0 }},
    "vulnerabilities": [
        {{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0
        }}
    ]
}}
"""

    # 3. Bedrock/LLM 클라이언트 및 페이로드 설정
    client = boto3.client(service_name='bedrock-runtime', region_name='ap-northeast-1')
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
        parsed = extract_json_from_text(result_text)
        if parsed is not None:
            return parsed
        print("LLM 응답:", result_text.strip())
        return {
            "summary": {"high": 0, "medium": 0, "low": 0},
            "vulnerabilities": [],
            "raw_output": result_text.strip()
        }

    except Exception as e:
        print(f"오류 발생: {e}")
        return None
    
def resolve_doc_path(relative_path: str) -> str:
    """
    relative_path가 'document/sqs_flag_shop.json'으로 들어올 경우를 대비
    """
    # 1. 넘겨받은 경로가 비어있는지 확인
    if not relative_path:
        return "경로 없음"
        
    # 2. BASE_DIR(backend/llm) -> ..(backend) -> relative_path(document/...)
    full_path = os.path.normpath(os.path.join(BASE_DIR, "..", relative_path))
    return full_path

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