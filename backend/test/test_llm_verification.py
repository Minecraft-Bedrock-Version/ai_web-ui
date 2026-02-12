"""
=================================================================
테스트 1: LLM 검증 동작 확인 (Primary Task 실패 → Secondary Task 전환)
=================================================================

방법 A: 프롬프트에 rag_scenario_valid 필드를 추가하여 LLM이 직접
        "재현 가능/불가능"을 출력 → 자동 판정
방법 B: 프로덕션 프롬프트 그대로 사용 → LLM 원문 응답 저장 → 수동 분석

실행 방법 (backend 폴더에서):
  python test/test_llm_verification.py          → 방법 A + B 모두 실행
  python test/test_llm_verification.py --method A  → 방법 A만
  python test/test_llm_verification.py --method B  → 방법 B만
  python test/test_llm_verification.py --dummy 1   → dummy1만 테스트
  python test/test_llm_verification.py --dummy 2   → dummy2만 테스트

⚠️ 사전 조건:
  1. Qdrant 서버 실행 중 (http://localhost:6333)
  2. AWS 자격 증명 설정 (Bedrock 접근)
  3. pandyo collection에 데이터 임베딩 완료
=================================================================
"""

import boto3
import json
import os
import sys
import re
import argparse
from datetime import datetime
from typing import Optional, Dict, Any

# =================================================================
# 경로 설정
# =================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.normpath(os.path.join(BASE_DIR, ".."))

# 더미 인프라 파일 경로
DUMMY1_PATH = os.path.join(BASE_DIR, "iam_privesc_by_key_rotation(dummy1).json")
DUMMY2_PATH = os.path.join(BASE_DIR, "iam_privesc_by_key_rotation(dummy2).json")
ORIGINAL_PATH = os.path.join(BASE_DIR, "iam_privesc_by_key_rotation.json")

# 취약점 컨텍스트 문서 경로
CONTEXT_PATH = os.path.join(BACKEND_DIR, "document", "iam_privesc_by_key_rotation.json")

# 결과 저장 경로
RESULT_DIR = os.path.join(BASE_DIR, "test_results")

# Bedrock 설정
REGION = "ap-northeast-1"
EMBED_MODEL_ID = "cohere.embed-v4:0"
LLM_MODEL_ID = "openai.gpt-oss-120b-1:0"
COLLECTION_NAME = "pandyo"


# =================================================================
# 유틸리티
# =================================================================
def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "ℹ️", "OK": "✅", "WARN": "⚠️", "FAIL": "❌", "TEST": "🧪"}
    print(f"[{timestamp}] {prefix.get(level, '')} [{level}] {msg}")


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """mbv_llm_gpt.py의 extract_json_from_text와 동일"""
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
        print(f"JSON 파싱 실패: {e}")
    return None


def call_bedrock_llm(prompt_template: str) -> Optional[Dict[str, Any]]:
    """Bedrock LLM 호출 (mbv_llm_gpt.py와 동일한 설정)"""
    client = boto3.client(service_name='bedrock-runtime', region_name=REGION)

    payload = {
        "messages": [
            {
                "role": "system",
                "content": "너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다."
            },
            {
                "role": "user",
                "content": prompt_template
            }
        ],
        "max_tokens": 4096,
        "temperature": 0.2,
        "top_p": 0.9,
        "reasoning_effort": "low"
    }

    response = client.invoke_model(
        body=json.dumps(payload),
        modelId=LLM_MODEL_ID,
        accept='application/json',
        contentType='application/json'
    )
    response_body = json.loads(response.get('body').read())

    if 'choices' in response_body:
        result_text = response_body['choices'][0]['message']['content']
    else:
        result_text = response_body.get('completion', "")

    return result_text


def get_embedding(text, bedrock_client):
    """mbv_search.py와 동일한 임베딩 함수"""
    native_request = {
        "texts": [text],
        "input_type": "search_query",
        "truncate": "NONE"
    }
    response = bedrock_client.invoke_model(
        modelId=EMBED_MODEL_ID, body=json.dumps(native_request)
    )
    res_body = json.loads(response.get('body').read())
    embeddings = res_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]


def save_results(data, filename):
    os.makedirs(RESULT_DIR, exist_ok=True)
    filepath = os.path.join(RESULT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log(f"결과 저장: {filepath}", "OK")
    return filepath


# =================================================================
# STEP 1: RAG 벡터 검색 (동일)
# =================================================================
def step1_rag_search(dummy_data, bedrock_client, q_client):
    """
    mbv_search.py와 동일한 로직으로 RAG 검색 수행.
    dummy 인프라가 iam_privesc_by_key_rotation으로 매칭되는지 확인.
    """
    log("=" * 60)
    log("STEP 1: RAG 벡터 검색", "TEST")
    log("=" * 60)

    if "resources" in dummy_data:
        context_list = [res.get("content", {}) for res in dummy_data["resources"]]
        query_text = json.dumps(context_list, ensure_ascii=False)
    else:
        query_text = json.dumps(dummy_data, ensure_ascii=False)

    log(f"검색 데이터 길이: {len(query_text)} chars")
    log("Cohere embed-v4 임베딩 수행 중...")
    query_vector = get_embedding(query_text, bedrock_client)

    log("Qdrant 유사도 검색 수행 중...")
    search_response = q_client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=3
    )

    results = search_response.points
    rag_result = {
        "total_results": len(results),
        "hits": [],
        "top_hit": None,
        "description_path": None,
        "passed_threshold": False
    }

    if results:
        for i, hit in enumerate(results):
            p = hit.payload
            hit_info = {
                "rank": i + 1,
                "title": p.get("title", "제목 없음"),
                "score": round(hit.score, 4),
                "description": p.get("description", "없음")
            }
            rag_result["hits"].append(hit_info)
            log(f"  [{i+1}위] {hit_info['title']} | 유사도: {hit_info['score']}")

            if i == 0:
                rag_result["top_hit"] = hit_info
                rag_result["description_path"] = p.get("description", "no경로")
                rag_result["passed_threshold"] = hit.score >= 0.6

        top_title = results[0].payload.get("title", "")
        if "iam_privesc_by_key_rotation" in top_title:
            log("RAG가 iam_privesc_by_key_rotation 문서를 반환", "OK")
        else:
            log(f"RAG가 다른 문서를 반환: {top_title}", "WARN")
    else:
        log("매칭 결과 없음", "FAIL")

    return rag_result


# =================================================================
# STEP 2A: 방법 A - 수정된 프롬프트 (rag_scenario_valid 필드 포함)
# =================================================================
def step2a_llm_with_schema(target_infra_json: str, retrieved_context: str):
    """
    방법 A: 프롬프트 스키마에 rag_scenario_valid 필드를 추가하여
    LLM이 "재현 가능/불가능"을 명시적으로 출력하도록 함.
    → rag_scenario_valid 값만으로 자동 판정 가능.
    """
    log("")
    log("=" * 60)
    log("STEP 2A: LLM 분석 (방법 A - rag_scenario_valid 포함 스키마)", "TEST")
    log("=" * 60)

    prompt = f"""
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 단순한 설정 오류 나열이 아니라, 현실적인 공격자가 실제로 악용 가능한 권한 조합과 신뢰 경계 붕괴 시나리오를 논리적으로 증명한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{target_infra_json}

[분석 실행 전략 (반드시 준수)]
1. **Primary Task (RAG 시나리오 검증):**
   - 최우선적으로 상기 '컨텍스트'에 명시된 공격 기법이 '입력된 인프라'에서 실제로 재현 가능한지 검증하라.
   - 컨텍스트의 attack_path 각 단계가 인프라에서 성립하는지 하나씩 확인하라.
   - 재현 가능 여부를 rag_scenario_valid 필드에 true/false로 명시하라.
   - 재현 불가능한 경우, 누락된 요소를 missing_components에 나열하라.
   - 해당 시나리오가 성립한다면 이를 vulnerabilities에 반드시 포함해야 한다.

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
    "rag_scenario_valid": true 또는 false,
    "rag_scenario_reason": "RAG 시나리오가 재현 가능/불가능한 이유를 한 문장으로",
    "missing_components": ["재현 불가 시 누락된 권한이나 리소스. 재현 가능 시 빈 배열"],
    "summary": {{ "high": 0, "medium": 0, "low": 0 }},
    "vulnerabilities": [
        {{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "source": "rag_primary 또는 zero_base_secondary"
        }}
    ]
}}
"""

    log("Bedrock LLM 호출 중... (약 30초~1분 소요)")
    raw_text = call_bedrock_llm(prompt)
    parsed = extract_json_from_text(raw_text)

    return {
        "raw_text": raw_text,
        "parsed": parsed
    }


# =================================================================
# STEP 2B: 방법 B - 프로덕션 프롬프트 (mbv_llm_gpt.py와 100% 동일)
# =================================================================
def step2b_llm_production(target_infra_json: str, retrieved_context: str):
    """
    방법 B: mbv_llm_gpt.py의 run_security_analysis와 100% 동일한 프롬프트 사용.
    LLM 원문 응답을 그대로 저장하여 수동 분석 가능.
    """
    log("")
    log("=" * 60)
    log("STEP 2B: LLM 분석 (방법 B - 프로덕션 프롬프트 그대로)", "TEST")
    log("=" * 60)

    # mbv_llm_gpt.py line 75-120과 100% 동일한 프롬프트
    prompt = f"""
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

    log("Bedrock LLM 호출 중... (약 30초~1분 소요)")
    raw_text = call_bedrock_llm(prompt)
    parsed = extract_json_from_text(raw_text)

    return {
        "raw_text": raw_text,
        "parsed": parsed
    }


# =================================================================
# STEP 3A: 방법 A 자동 판정
# =================================================================
def step3a_auto_verdict(llm_result, dummy_name):
    """
    방법 A 판정: rag_scenario_valid 필드값으로 자동 판정.
    키워드 매칭이 아니라 LLM이 직접 출력한 boolean 값을 사용.
    """
    log("")
    log("=" * 60)
    log("STEP 3A: 자동 판정 (rag_scenario_valid 기반)", "TEST")
    log("=" * 60)

    parsed = llm_result.get("parsed")
    analysis = {
        "method": "A (스키마 기반 자동 판정)",
        "dummy_name": dummy_name,
        "verdict": "UNKNOWN"
    }

    if parsed is None:
        log("LLM 응답 JSON 파싱 실패", "FAIL")
        log(f"원문 응답:\n{llm_result.get('raw_text', '없음')[:500]}")
        analysis["verdict"] = "PARSE_ERROR"
        return analysis

    # --- 핵심: rag_scenario_valid 필드 확인 ---
    rag_valid = parsed.get("rag_scenario_valid")
    rag_reason = parsed.get("rag_scenario_reason", "이유 없음")
    missing = parsed.get("missing_components", [])
    vulns = parsed.get("vulnerabilities", [])
    summary = parsed.get("summary", {})

    log(f"rag_scenario_valid: {rag_valid}")
    log(f"rag_scenario_reason: {rag_reason}")
    log(f"missing_components: {missing}")
    log(f"취약점 수: {len(vulns)}")
    log(f"심각도: High={summary.get('high',0)} Medium={summary.get('medium',0)} Low={summary.get('low',0)}")

    # source 별 취약점 분류
    primary_vulns = [v for v in vulns if v.get("source") == "rag_primary"]
    secondary_vulns = [v for v in vulns if v.get("source") == "zero_base_secondary"]
    untagged_vulns = [v for v in vulns if v.get("source") not in ("rag_primary", "zero_base_secondary")]

    log(f"\nPrimary(RAG) 취약점: {len(primary_vulns)}개")
    for v in primary_vulns:
        log(f"  → [{v.get('severity','')}] {v.get('title','')}")

    log(f"Secondary(Zero-Base) 취약점: {len(secondary_vulns)}개")
    for v in secondary_vulns:
        log(f"  → [{v.get('severity','')}] {v.get('title','')}")

    if untagged_vulns:
        log(f"미분류 취약점: {len(untagged_vulns)}개", "WARN")
        for v in untagged_vulns:
            log(f"  → [{v.get('severity','')}] {v.get('title','')}")

    # --- 판정 로직 ---
    log("\n" + "-" * 40)

    if rag_valid is False:
        # LLM이 "재현 불가"라고 판단 → 올바른 판단
        if len(secondary_vulns) + len(untagged_vulns) > 0:
            analysis["verdict"] = "PASS"
            log("🎉 판정: PASS", "OK")
            log("  LLM이 RAG 시나리오 재현 불가를 인지하고 Secondary Task 수행", "OK")
        else:
            analysis["verdict"] = "PARTIAL_PASS"
            log("판정: PARTIAL_PASS", "WARN")
            log("  RAG 재현 불가 인지는 정확하나, Secondary 취약점을 찾지 못함", "WARN")

    elif rag_valid is True:
        # LLM이 "재현 가능"이라고 판단 → 오탐 (dummy에는 핵심 요소 없음)
        analysis["verdict"] = "FAIL_FALSE_POSITIVE"
        log("판정: FAIL (False Positive)", "FAIL")
        log("  LLM이 재현 불가능한 시나리오를 가능하다고 잘못 판단", "FAIL")

    else:
        # rag_scenario_valid 필드가 없거나 null
        analysis["verdict"] = "FIELD_MISSING"
        log("판정: FIELD_MISSING", "WARN")
        log("  LLM이 rag_scenario_valid 필드를 출력하지 않음", "WARN")

    analysis["rag_scenario_valid"] = rag_valid
    analysis["rag_scenario_reason"] = rag_reason
    analysis["missing_components"] = missing
    analysis["primary_count"] = len(primary_vulns)
    analysis["secondary_count"] = len(secondary_vulns) + len(untagged_vulns)

    return analysis


# =================================================================
# STEP 3B: 방법 B 수동 분석용 저장
# =================================================================
def step3b_save_for_review(llm_result, dummy_name, timestamp):
    """
    방법 B: 프로덕션 프롬프트 응답을 파일로 저장하여 수동 분석 가능.
    """
    log("")
    log("=" * 60)
    log("STEP 3B: 수동 분석용 저장 (프로덕션 프롬프트 결과)", "TEST")
    log("=" * 60)

    parsed = llm_result.get("parsed")
    raw_text = llm_result.get("raw_text", "")

    # 파싱 결과 간단 요약 출력
    if parsed:
        vulns = parsed.get("vulnerabilities", [])
        summary = parsed.get("summary", {})
        log(f"취약점 수: {len(vulns)}")
        log(f"심각도: High={summary.get('high',0)} Medium={summary.get('medium',0)} Low={summary.get('low',0)}")
        for v in vulns:
            log(f"  → [{v.get('severity','')}] {v.get('title','')}")
    else:
        log("JSON 파싱 실패 - 원문 그대로 저장", "WARN")

    # 파일 저장
    safe_name = dummy_name.replace(" ", "_").replace("(", "").replace(")", "")
    result_data = {
        "test_info": {
            "method": "B (프로덕션 프롬프트 - 수동 분석용)",
            "dummy_name": dummy_name,
            "timestamp": timestamp,
            "note": "이 결과는 실제 프로덕션 코드(mbv_llm_gpt.py)와 동일한 프롬프트로 생성됨"
        },
        "raw_text": raw_text,
        "parsed_json": parsed
    }

    filename = f"method_B_{safe_name}_{timestamp}.json"
    filepath = save_results(result_data, filename)

    log("")
    log("📄 수동 분석 안내:", "INFO")
    log(f"  파일: {filepath}")
    log("  확인 포인트:")
    log("    1. LLM이 RAG 시나리오(iam_privesc_by_key_rotation) 재현 불가를 언급했는가?")
    log("    2. secretsmanager, GetSecretValue 관련 분석이 '부재'로 언급되었는가?")
    log("    3. Secondary Task(일반 보안 점검) 결과가 포함되었는가?")

    return {
        "method": "B (수동 분석용)",
        "dummy_name": dummy_name,
        "saved_to": filepath,
        "vuln_count": len(parsed.get("vulnerabilities", [])) if parsed else 0,
        "verdict": "MANUAL_REVIEW_REQUIRED"
    }


# =================================================================
# 단일 더미 테스트 실행
# =================================================================
def run_test(dummy_path, dummy_name, methods):
    """하나의 dummy 파일에 대해 선택된 방법으로 테스트 실행"""
    log(f"\n{'#'*60}")
    log(f"테스트 시작: {dummy_name}")
    log(f"파일: {os.path.basename(dummy_path)}")
    log(f"실행 방법: {', '.join(methods)}")
    log(f"{'#'*60}\n")

    # 데이터 로드
    with open(dummy_path, "r", encoding="utf-8") as f:
        dummy_data = json.load(f)

    with open(CONTEXT_PATH, "r", encoding="utf-8") as f:
        retrieved_context = f.read()

    target_infra_json = json.dumps(dummy_data, ensure_ascii=False)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 클라이언트 초기화
    from qdrant_client import QdrantClient
    bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)
    q_client = QdrantClient(url="http://localhost:6333")

    test_result = {
        "dummy_file": os.path.basename(dummy_path),
        "dummy_name": dummy_name,
        "timestamp": ts,
        "steps": {}
    }

    # --- Step 1: RAG 검색 ---
    try:
        rag_result = step1_rag_search(dummy_data, bedrock, q_client)
        test_result["steps"]["step1_rag"] = rag_result
    except Exception as e:
        log(f"Step 1 실패: {e}", "FAIL")
        test_result["steps"]["step1_rag"] = {"error": str(e)}
        return test_result

    if not rag_result.get("passed_threshold"):
        log("RAG 유사도 임계값 미달 - LLM 테스트 스킵", "WARN")
        return test_result

    # --- 방법 A ---
    if "A" in methods:
        try:
            llm_a = step2a_llm_with_schema(target_infra_json, retrieved_context)
            verdict_a = step3a_auto_verdict(llm_a, dummy_name)
            test_result["steps"]["method_A"] = {
                "llm_parsed": llm_a.get("parsed"),
                "llm_raw_text": llm_a.get("raw_text"),
                "verdict": verdict_a
            }
        except Exception as e:
            log(f"방법 A 실패: {e}", "FAIL")
            test_result["steps"]["method_A"] = {"error": str(e)}

    # --- 방법 B ---
    if "B" in methods:
        try:
            llm_b = step2b_llm_production(target_infra_json, retrieved_context)
            review_b = step3b_save_for_review(llm_b, dummy_name, ts)
            test_result["steps"]["method_B"] = {
                "llm_parsed": llm_b.get("parsed"),
                "llm_raw_text": llm_b.get("raw_text"),
                "review": review_b
            }
        except Exception as e:
            log(f"방법 B 실패: {e}", "FAIL")
            test_result["steps"]["method_B"] = {"error": str(e)}

    return test_result


# =================================================================
# 메인
# =================================================================
def main():
    parser = argparse.ArgumentParser(description="LLM 검증 동작 테스트")
    parser.add_argument("--method", choices=["A", "B", "AB"], default="AB",
                        help="테스트 방법 선택: A(스키마 자동판정), B(수동분석), AB(둘다)")
    parser.add_argument("--dummy", choices=["1", "2", "all"], default="all",
                        help="테스트 대상: 1(dummy1), 2(dummy2), all(둘다)")
    args = parser.parse_args()

    methods = list(args.method.upper())  # "AB" → ["A", "B"]

    log("=" * 60)
    log("LLM 검증 동작 테스트", "TEST")
    log(f"실행 방법: {methods}")
    log("=" * 60)

    targets = []
    if args.dummy in ("1", "all"):
        targets.append((DUMMY1_PATH, "dummy1 (구조 유사, 핵심 권한 부재)"))
    if args.dummy in ("2", "all"):
        targets.append((DUMMY2_PATH, "dummy2 (최소 구조, Role/SecretsManager 완전 제거)"))

    all_results = {
        "test_suite": "LLM 검증 동작 확인",
        "methods": methods,
        "timestamp": datetime.now().isoformat(),
        "tests": []
    }

    for dummy_path, dummy_name in targets:
        if not os.path.exists(dummy_path):
            log(f"파일 없음: {dummy_path}", "FAIL")
            continue

        result = run_test(dummy_path, dummy_name, methods)
        all_results["tests"].append(result)

    # 전체 결과 저장
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_results(all_results, f"llm_test_full_{ts}.json")

    # --- 최종 요약 ---
    log("\n" + "#" * 60)
    log("최종 요약", "TEST")
    log("#" * 60)

    for test in all_results["tests"]:
        log(f"\n📁 {test['dummy_name']}")

        # 방법 A 요약
        ma = test.get("steps", {}).get("method_A", {})
        if ma:
            v = ma.get("verdict", {})
            if isinstance(v, dict):
                verdict = v.get("verdict", "N/A")
                emoji = "✅" if "PASS" in verdict else "❌" if "FAIL" in verdict else "⚠️"
                log(f"  방법 A: {emoji} {verdict}")
                if v.get("rag_scenario_reason"):
                    log(f"         이유: {v['rag_scenario_reason']}")
                if v.get("missing_components"):
                    log(f"         누락: {v['missing_components']}")
            else:
                log(f"  방법 A: ⚠️ {ma}")

        # 방법 B 요약
        mb = test.get("steps", {}).get("method_B", {})
        if mb:
            r = mb.get("review", {})
            if isinstance(r, dict):
                log(f"  방법 B: 📄 수동 분석 필요 (취약점 {r.get('vuln_count', 0)}개)")
                log(f"         저장: {r.get('saved_to', 'N/A')}")
            else:
                log(f"  방법 B: ⚠️ {mb}")

    log("\n" + "=" * 60)
    log("테스트 완료!", "OK")


if __name__ == "__main__":
    main()
