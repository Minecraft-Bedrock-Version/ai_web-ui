# ============================================================
# 방법 1: <reasoning> 단순화 + reasoning_effort: medium
# - 프롬프트에 reasoning 최소화 지시 추가
# - reasoning_effort: "medium"
# ============================================================
import json
import boto3
import os
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
import re
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_JSON_PATH = os.path.join(BASE_DIR, "..", "json", "pandyo", "search_pandyo.json")

def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    text = re.sub(r'<reasoning>.*?</reasoning>', '', text, flags=re.DOTALL)
    text = re.sub(r'```(?:json)?\s*([\s\S]*?)\s*```', r'\1', text)
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            json_str = text[start:end+1]
            parsed = json.loads(json_str)
            if "vulnerabilities" in parsed and "summary" not in parsed:
                v = parsed["vulnerabilities"]
                parsed["summary"] = {
                    "high": len([x for x in v if str(x.get("severity")).lower() == "high"]),
                    "medium": len([x for x in v if str(x.get("severity")).lower() == "medium"]),
                    "low": len([x for x in v if str(x.get("severity")).lower() == "low"]),
                }
            return parsed
    except Exception as e:
        print(f"JSON 파싱 최종 실패: {e}")
    return None

def run_security_analysis(target_infra_json: str, retrieved_context: str) -> Optional[Dict[str, Any]]:
    """
    방법 1: reasoning 단순화 + medium effort
    - 프롬프트에 reasoning 최소화 지시 추가
    """
    # 수정된 프롬프트: reasoning 최소화 지시 추가
    prompt_template = f"""
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 단순한 설정 오류 나열이 아니라, 현실적인 공격자가 실제로 악용 가능한 권한 조합과 신뢰 경계 붕괴 시나리오를 논리적으로 증명한다.

[중요] reasoning 작성 시 핵심만 간결하게 작성하라. 장황한 설명 없이 판단 근거만 기술하라.

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

    client = boto3.client(service_name='bedrock-runtime', region_name='ap-northeast-1')
    model_id = 'openai.gpt-oss-120b-1:0'

    payload = {
        "messages": [
            {
                "role": "system",
                "content": "너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다. reasoning은 핵심만 간결하게 작성하라."
            },
            {
                "role": "user",
                "content": prompt_template
            }
        ],
        "max_tokens": 2096,
        "temperature": 0.2,
        "top_p": 0.9,
        "reasoning_effort": "medium"  # 방법 1: medium
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
        
        # 토큰 사용량 추출 및 로깅
        usage = response_body.get('usage', {})
        input_tokens = usage.get('prompt_tokens', usage.get('input_tokens', 'N/A'))
        output_tokens = usage.get('completion_tokens', usage.get('output_tokens', 'N/A'))
        total_tokens = usage.get('total_tokens', 'N/A')
        
        print("\n" + "="*60)
        print("📊 [방법 1] Simplified Reasoning + Medium Effort 결과")
        print("="*60)
        print(f"⏱️  실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📥 Input Tokens: {input_tokens}")
        print(f"📤 Output Tokens: {output_tokens}")
        print(f"📊 Total Tokens: {total_tokens}")
        print("="*60)
        
        if 'choices' in response_body:
            result_text = response_body['choices'][0]['message']['content']
        else:
            result_text = response_body.get('completion', "")
        
        parsed = extract_json_from_text(result_text)
        
        if parsed is not None:
            print("\n✅ 분석 결과:")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
            
            # 결과 요약
            if "summary" in parsed:
                print(f"\n📋 취약점 요약: High={parsed['summary'].get('high',0)}, Medium={parsed['summary'].get('medium',0)}, Low={parsed['summary'].get('low',0)}")
            if "vulnerabilities" in parsed:
                print(f"🔍 총 탐지된 취약점 수: {len(parsed['vulnerabilities'])}개")
            return parsed
            
        print("LLM 응답:", result_text.strip())
        return {
            "summary": {"high": 0, "medium": 0, "low": 0},
            "vulnerabilities": [],
            "raw_output": result_text.strip()
        }

    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        return None

def resolve_doc_path(relative_path: str) -> str:
    if not relative_path:
        return "경로 없음"
    full_path = os.path.normpath(os.path.join(BASE_DIR, "..", relative_path))
    return full_path

def run_mbv_llm(description: str) -> str:
    if not os.path.exists(TARGET_JSON_PATH):
        raise FileNotFoundError(f"분석 대상 파일 없음:{TARGET_JSON_PATH}")
    with open(TARGET_JSON_PATH, "r", encoding='utf-8') as f:
        target_infra_json = json.dumps(json.load(f), ensure_ascii=False)

    doc_path = resolve_doc_path(description)
    if not os.path.exists(doc_path):
        raise FileNotFoundError(f"문서 없음: {doc_path}")

    with open(doc_path, "r", encoding="utf-8") as f:
        retrieved_context = f.read()

    analysis_result = run_security_analysis(target_infra_json, retrieved_context)
    return analysis_result

# 직접 실행용
if __name__ == "__main__":
    print("\n🚀 [방법 1] Simplified Reasoning + Medium Effort 테스트 시작...")
    print("설정: reasoning 단순화 지시 + reasoning_effort='medium'")
    
    # 기본 RAG 문서 경로 (필요시 수정)
    description = "document/sqs_flag_shop.json"
    
    try:
        result = run_mbv_llm(description)
        print("\n✅ 테스트 완료!")
    except Exception as e:
        print(f"❌ 테스트 실패: {e}")
