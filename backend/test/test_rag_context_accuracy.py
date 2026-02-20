#!/usr/bin/env python3
"""
==========================================================
RAG Context 정확도 테스트 (Baseline + Test 1~5)
==========================================================
실행: python3 test_rag_context_accuracy.py [baseline|test1|test2|test3|test4|test5|all]
환경: EC2 (Bedrock + Qdrant)
"""

import json
import sys
import os
import re
import time
import boto3
from datetime import datetime

# ──────────────────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────────────────
REGION = "ap-northeast-1"
MODEL_ID = "openai.gpt-oss-120b-1:0"
MAX_TOKENS = 4096

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOC_DIR = os.path.join(BASE_DIR, "..", "document")

# RAG 유사도 실측 결과 순위대로 문서 매핑
DOC_FILES = {
    "vulnerable_lambda": os.path.join(DOC_DIR, "vulnerable_lambda.json"),
    "eventbridge_target": os.path.join(DOC_DIR, "eventbridge_target.json"),
    "iam_privesc_by_key_rotation": os.path.join(DOC_DIR, "iam_privesc_by_key_rotation.json"),
    "lambda_privesc": os.path.join(DOC_DIR, "lambda_privesc.json"),
}

# 모델 최대 출력 토큰: 33,000 (context window: 128K)
# MAX_TOKENS는 테스트별로 다르게 설정 가능

# Bedrock 클라이언트
client = boto3.client(service_name='bedrock-runtime', region_name=REGION)

# ──────────────────────────────────────────────────────────
# 테스트 대상 인프라 JSON
# ──────────────────────────────────────────────────────────
TARGET_INFRA = {
    "schema_version": "1.5",
    "nodes": [
        {
            "node_id": "288528695623:iam_user:even",
            "type": "iam_user",
            "name": "even",
            "properties": {
                "inline_policies": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "lambda:ListFunctions",
                            "lambda:GetFunction",
                            "events:PutTargets",
                            "events:PutRule",
                            "iam:List*",
                            "iam:Get*",
                            "iam:CreateAccessKey"
                        ],
                        "Resource": "*"
                    }
                ],
                "attached_policies": [],
                "group_policies": []
            }
        },
        {
            "node_id": "288528695623:iam_role:admin_secrets",
            "type": "iam_role",
            "name": "admin_secrets",
            "properties": {
                "assume_role_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Principal": {"AWS": "arn:aws:iam::288528695623:user/admin_mbv"}
                        }
                    ]
                },
                "inline_policies": [
                    {
                        "PolicyName": "secretsmanager",
                        "Statement": [
                            {
                                "Action": ["secretsmanager:ListSecrets", "secretsmanager:GetSecretValue"],
                                "Effect": "Allow",
                                "Resource": ["*"]
                            }
                        ]
                    }
                ],
                "attached_policies": []
            }
        },
        {
            "node_id": "288528695623:iam_role:lambda-role-mbv",
            "type": "iam_role",
            "name": "lambda-role-mbv",
            "properties": {
                "assume_role_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Principal": {"Service": "lambda.amazonaws.com"}
                        }
                    ]
                },
                "inline_policies": [],
                "attached_policies": [
                    {
                        "PolicyName": "lambda-policy-mbv",
                        "Statement": [
                            {"Action": ["cloudtrail:LookupEvents"], "Effect": "Allow", "Resource": "*"},
                            {"Action": ["iam:AttachUserPolicy"], "Effect": "Allow", "Resource": "*"},
                            {"Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Effect": "Allow", "Resource": "arn:aws:logs:*:*:*"}
                        ]
                    }
                ]
            }
        },
        {"node_type": "secretsmanager", "node_id": "288528695623:us-east-1:secretsmanager:secret_key"},
        {
            "node_id": "288528695623:iam_user:admin_mbv",
            "type": "iam_user",
            "name": "admin_mbv",
            "properties": {
                "inline_policies": [],
                "attached_policies": [
                    {"Effect": "Allow", "Action": ["sts:AssumeRole", "iam:List*", "iam:Get*"], "Resource": "*"}
                ],
                "group_policies": []
            }
        },
        {
            "node_id": "288528695623:us-east-1:eventbridge:iam_taguser",
            "type": "eventbridge",
            "name": "iam_taguser",
            "attributes": {
                "state": "ENABLED",
                "target_arn": ["arn:aws:lambda:us-east-1:288528695623:function:tag-lambda-mbv"]
            }
        },
        {
            "node_id": "288528695623:us-east-1:lambda:tag-lambda-mbv",
            "type": "lambda",
            "name": "tag-lambda-mbv",
            "properties": {"event_source_arn": []}
        }
    ],
    "edges": [
        {"id": "edge:tag-lambda-mbv:ASSUMES_ROLE:lambda-role-mbv", "src": "288528695623:us-east-1:lambda:tag-lambda-mbv", "dst": "288528695623:iam_role:lambda-role-mbv", "relation": "LAMBDA_ASSUMES_ROLE", "directed": True, "conditions": "This Lambda function executes with the permissions of lambda-role-mbv role."},
        {"id": "edge:even:IAM_USER_MANAGE_EVENTBRIDGE:iam_taguser", "src": "288528695623:iam_user:even", "dst": "288528695623:us-east-1:eventbridge:iam_taguser", "relation": "IAM_USER_MANAGE_EVENTBRIDGE", "directed": True, "conditions": "User can modify EventBridge rules to redirect triggers."},
        {"id": "edge:even:IAM_USER_CREATE_USER_ACCESSKEY:admin_mbv", "src": "288528695623:iam_user:even", "dst": "288528695623:iam_user:admin_mbv", "relation": "IAM_USER_CREATE_USER_ACCESSKEY", "directed": True, "conditions": "This user can generate access keys for other users."},
        {"id": "edge:admin_secrets:IAM_ROLE_ACCESS_SECRETSMANAGER:secret_key", "src": "288528695623:iam_role:admin_secrets", "dst": "288528695623:us-east-1:secretsmanager:secret_key", "relation": "IAM_ROLE_ACCESS_SECRETSMANAGER", "directed": True, "conditions": "This role gives you access to Secrets Manager."},
        {"id": "edge:even:IAM_USER_ACCESS_LAMBDA:tag-lambda-mbv", "src": "288528695623:iam_user:even", "dst": "288528695623:us-east-1:lambda:tag-lambda-mbv", "relation": "IAM_USER_ACCESS_LAMBDA", "directed": True, "conditions": "This User has access to Lambda."},
        {"id": "edge:iam_taguser:TRIGGERS:tag-lambda-mbv", "src": "288528695623:us-east-1:eventbridge:iam_taguser", "dst": "288528695623:us-east-1:lambda:tag-lambda-mbv", "relation": "EVENTBRIDGE_TRIGGERS_LAMBDA", "directed": True, "conditions": "Rule triggers this Lambda. Attackers can modify 'Input' to exploit it."},
        {"id": "edge:admin_mbv:ASSUME_ROLE:admin_secrets", "src": "288528695623:iam_user:admin_mbv", "dst": "288528695623:iam_role:admin_secrets", "relation": "ASSUME_ROLE", "directed": True, "conditions": "This role explicitly trusts this IAM User."},
        {"id": "edge:tag-lambda-mbv:ASSUME_ROLE:lambda-role-mbv", "src": "288528695623:us-east-1:lambda:tag-lambda-mbv", "dst": "288528695623:iam_role:lambda-role-mbv", "relation": "ASSUME_ROLE", "directed": True, "conditions": "A role that a Lambda function can assume."},
        {"id": "edge:lambda-role-mbv:ELEVATES_PRIVILEGE:admin_mbv", "src": "288528695623:iam_role:lambda-role-mbv", "dst": "288528695623:iam_user:admin_mbv", "relation": "ELEVATES_PRIVILEGE", "directed": True, "conditions": "This role can elevate privileges of user admin_mbv via iam:AttachUserPolicy."},
        {"id": "edge:lambda-role-mbv:ELEVATES_PRIVILEGE:even", "src": "288528695623:iam_role:lambda-role-mbv", "dst": "288528695623:iam_user:even", "relation": "ELEVATES_PRIVILEGE", "directed": True, "conditions": "This role can elevate privileges of user even via iam:AttachUserPolicy."}
    ]
}

TARGET_INFRA_STR = json.dumps(TARGET_INFRA, ensure_ascii=False)


# ──────────────────────────────────────────────────────────
# 유틸리티
# ──────────────────────────────────────────────────────────
def load_doc(name):
    """문서 파일 읽기"""
    path = DOC_FILES[name]
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def extract_json_from_text(text):
    """LLM 출력에서 JSON 추출 (mbv_llm_gpt.py와 동일 로직)"""
    text = re.sub(r'<reasoning>.*?</reasoning>', '', text, flags=re.DOTALL)
    text = re.sub(r'```(?:json)?\s*([\s\S]*?)\s*```', r'\1', text)
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            json_str = text[start:end+1]
            parsed = json.loads(json_str)
            return parsed
    except Exception as e:
        print(f"  ❌ JSON 파싱 실패: {e}")
    return None


def call_llm(prompt, system_msg=None, max_tokens=MAX_TOKENS, temperature=0.2):
    """Bedrock LLM 호출 + 메타데이터 반환"""
    if system_msg is None:
        system_msg = "너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다."

    payload = {
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": 0.9,
        "reasoning_effort": "low"
    }

    start_time = time.time()
    response = client.invoke_model(
        body=json.dumps(payload),
        modelId=MODEL_ID,
        accept='application/json',
        contentType='application/json'
    )
    elapsed = time.time() - start_time

    response_body = json.loads(response.get('body').read())

    # 텍스트 추출
    if 'choices' in response_body:
        result_text = response_body['choices'][0]['message']['content']
        finish_reason = response_body['choices'][0].get('finish_reason', 'unknown')
    else:
        result_text = response_body.get('completion', "")
        finish_reason = response_body.get('stop_reason', 'unknown')

    # 토큰 사용량 추출
    usage = response_body.get('usage', {})
    input_tokens = usage.get('prompt_tokens', usage.get('input_tokens', -1))
    output_tokens = usage.get('completion_tokens', usage.get('output_tokens', -1))

    return {
        "raw_text": result_text,
        "parsed": extract_json_from_text(result_text),
        "finish_reason": finish_reason,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "response_time_sec": round(elapsed, 2),
        "truncated": finish_reason == "length",
    }


def build_existing_prompt(retrieved_context):
    """기존 mbv_llm_gpt.py와 완전히 동일한 프롬프트"""
    return f"""
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 단순한 설정 오류 나열이 아니라, 현실적인 공격자가 실제로 악용 가능한 권한 조합과 신뢰 경계 붕괴 시나리오를 논리적으로 증명한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

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


def print_result(test_name, result, context_docs):
    """결과 출력"""
    print(f"\n{'=' * 70}")
    print(f"📋 [{test_name}] 결과")
    print(f"{'=' * 70}")
    print(f"  문서: {context_docs}")
    print(f"  응답 시간: {result['response_time_sec']}초")
    print(f"  Input 토큰: {result['input_tokens']}")
    print(f"  Output 토큰: {result['output_tokens']}")
    print(f"  finish_reason: {result['finish_reason']}")
    print(f"  잘림 여부: {'⚠️ 잘림!' if result['truncated'] else '✅ 정상'}")

    parsed = result.get("parsed")
    if parsed is None:
        print(f"\n  ❌ JSON 파싱 실패 — LLM 원문 출력:")
        print(f"  {result['raw_text'][:500]}...")
        return

    vulns = parsed.get("vulnerabilities", [])
    summary = parsed.get("summary", {})
    print(f"\n  📊 Summary: High={summary.get('high',0)} / Medium={summary.get('medium',0)} / Low={summary.get('low',0)}")
    print(f"  📊 취약점 수: {len(vulns)}")

    for i, v in enumerate(vulns):
        title = v.get("title", "N/A")
        sev = v.get("severity", "N/A")
        score = v.get("cvss_score", "N/A")
        source = v.get("source", "-")
        conf = v.get("confidence", "-")
        print(f"\n  [{i+1}] [{sev.upper()}] {title}")
        print(f"      CVSS: {score} | source: {source} | confidence: {conf}")
        paths = v.get("attackPath", [])
        if paths:
            for p in paths[:3]:
                print(f"      → {p}")
            if len(paths) > 3:
                print(f"      → ... (+{len(paths)-3} 단계)")

    print(f"\n{'─' * 70}")


def save_log(test_name, result, context_docs):
    """결과를 JSON 로그 파일로 저장"""
    log = {
        "test_id": test_name,
        "timestamp": datetime.now().isoformat(),
        "context_docs": context_docs,
        "input_tokens": result["input_tokens"],
        "output_tokens": result["output_tokens"],
        "response_time_sec": result["response_time_sec"],
        "finish_reason": result["finish_reason"],
        "truncated": result["truncated"],
        "parsed_success": result["parsed"] is not None,
        "vuln_count": len(result["parsed"].get("vulnerabilities", [])) if result["parsed"] else 0,
        "result": result["parsed"],
    }

    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{test_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
    print(f"  📁 로그 저장: {log_path}")
    return log


# ──────────────────────────────────────────────────────────
# Baseline: 기존 프롬프트 + Top-1 (vulnerable_lambda)
# ──────────────────────────────────────────────────────────
def run_baseline():
    print("\n" + "🔵" * 35)
    print("  Baseline: 기존 프롬프트 + Top-1 (vulnerable_lambda)")
    print("🔵" * 35)

    doc = load_doc("vulnerable_lambda")
    prompt = build_existing_prompt(doc)
    result = call_llm(prompt)

    context_docs = ["vulnerable_lambda"]
    print_result("Baseline", result, context_docs)
    return save_log("baseline", result, context_docs)


# ──────────────────────────────────────────────────────────
# Test 1: 기존 프롬프트 + Top-2 (프롬프트 변경 없음)
# ──────────────────────────────────────────────────────────
def run_test1():
    print("\n" + "🟢" * 35)
    print("  Test 1: 기존 프롬프트 + Top-2 (vulnerable_lambda + eventbridge_target)")
    print("🟢" * 35)

    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")

    # 프롬프트 동일 — retrieved_context에 문서 2개 이어 붙이기만 함
    retrieved_context = f"""[문서 1 - vulnerable_lambda]
{doc1}

[문서 2 - eventbridge_target]
{doc2}"""

    prompt = build_existing_prompt(retrieved_context)
    result = call_llm(prompt)

    context_docs = ["vulnerable_lambda", "eventbridge_target"]
    print_result("Test 1 (2 docs)", result, context_docs)
    return save_log("test1_2docs", result, context_docs)


# ──────────────────────────────────────────────────────────
# Test 2: 기존 프롬프트 + Top-3 (프롬프트 변경 없음)
# ──────────────────────────────────────────────────────────
def run_test2():
    print("\n" + "🟡" * 35)
    print("  Test 2: 기존 프롬프트 + Top-3 (+ iam_privesc_by_key_rotation)")
    print("🟡" * 35)

    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")
    doc3 = load_doc("iam_privesc_by_key_rotation")

    retrieved_context = f"""[문서 1 - vulnerable_lambda]
{doc1}

[문서 2 - eventbridge_target]
{doc2}

[문서 3 - iam_privesc_by_key_rotation]
{doc3}"""

    prompt = build_existing_prompt(retrieved_context)
    result = call_llm(prompt)

    context_docs = ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"]
    print_result("Test 2 (3 docs)", result, context_docs)
    return save_log("test2_3docs", result, context_docs)


# ──────────────────────────────────────────────────────────
# Test 3: 2단계 분리 호출 (새 프롬프트)
# ──────────────────────────────────────────────────────────
def run_test3():
    print("\n" + "🟠" * 35)
    print("  Test 3: 2단계 분리 호출 (Primary + Secondary)")
    print("🟠" * 35)

    # 유사도 0.7 이상 문서 모두 로드
    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")
    doc3 = load_doc("iam_privesc_by_key_rotation")

    retrieved_context = f"""[문서 1 - vulnerable_lambda (유사도: 0.8014)]
{doc1}

[문서 2 - eventbridge_target (유사도: 0.7964)]
{doc2}

[문서 3 - iam_privesc_by_key_rotation (유사도: 0.7200)]
{doc3}"""

    # ── Phase 1: Primary 전용 ──
    print("\n  ── Phase 1: Primary (RAG 시나리오 검증) ──")
    primary_prompt = f"""
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 RAG 문서들의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 각각 검증한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[분석 지침 (반드시 준수)]
1. 각 문서의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하라.
2. 재현 가능한 시나리오는 공격 경로를 단계별로 증명하라.
3. 재현 불가능한 시나리오는 구체적 사유를 명시하고 결과에서 제외하라.
4. 이 단계에서는 RAG 문서에 없는 추가 취약점을 탐색하지 마라.

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow 뿐만 아니라 Deny, SCP, Permissions Boundary 등을 모두 대조하여 실제 유효 권한을 계산하라.
2. **[Identity vs Resource-based Policy Interaction]**: IAM 정책과 리소스 기반 정책의 상호작용을 분석하여 신뢰 경계 붕괴를 식별하라.
3. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로를 시뮬레이션하라.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.

출력 형식
아래 스키마의 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0
        }}}}
    ]
}}}}
"""

    primary_result = call_llm(primary_prompt)
    print_result("Test 3 - Phase 1 (Primary)", primary_result, ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"])

    # Phase 1 결과 요약 (Phase 2에 전달)
    primary_summary = "없음"
    if primary_result["parsed"]:
        vulns = primary_result["parsed"].get("vulnerabilities", [])
        titles = [v.get("title", "") for v in vulns]
        primary_summary = "\n".join([f"- {t}" for t in titles])

    # ── Phase 2: Secondary 전용 ──
    print("\n  ── Phase 2: Secondary (Zero-Base 확장 탐지) ──")
    secondary_prompt = f"""
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 인프라에서 아직 식별되지 않은 추가 취약점을 탐색한다.

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

이미 식별된 취약점 (제외 대상 - 중복 보고 금지):
{primary_summary}

[분석 지침 (반드시 준수)]
1. 위에 이미 식별된 취약점은 중복 보고하지 마라.
2. 클라우드 보안 지식(OWASP, AWS Best Practices)을 총동원하여 인프라 전체를 스캔하라.
3. IAM 권한 오남용, 리소스 노출, 암호화 미비 등 치명적 취약점을 식별하여 보고하라.
4. sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로(Multi-hop Attack)를 시뮬레이션하라.

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow 뿐만 아니라 Deny, SCP, Permissions Boundary 등을 모두 대조하여 실제 유효 권한을 계산하라.
2. **[Identity vs Resource-based Policy Interaction]**: IAM 정책과 리소스 기반 정책의 상호작용을 분석하여 신뢰 경계 붕괴를 식별하라.
3. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.

출력 형식
아래 스키마의 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0
        }}}}
    ]
}}}}
"""

    secondary_result = call_llm(secondary_prompt)
    print_result("Test 3 - Phase 2 (Secondary)", secondary_result, ["zero_base_only"])

    # 통합 로그 저장
    combined_log = {
        "test_id": "test3_two_phase",
        "timestamp": datetime.now().isoformat(),
        "context_docs": ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"],
        "phase1": {
            "input_tokens": primary_result["input_tokens"],
            "output_tokens": primary_result["output_tokens"],
            "response_time_sec": primary_result["response_time_sec"],
            "finish_reason": primary_result["finish_reason"],
            "truncated": primary_result["truncated"],
            "vuln_count": len(primary_result["parsed"].get("vulnerabilities", [])) if primary_result["parsed"] else 0,
            "result": primary_result["parsed"],
        },
        "phase2": {
            "input_tokens": secondary_result["input_tokens"],
            "output_tokens": secondary_result["output_tokens"],
            "response_time_sec": secondary_result["response_time_sec"],
            "finish_reason": secondary_result["finish_reason"],
            "truncated": secondary_result["truncated"],
            "vuln_count": len(secondary_result["parsed"].get("vulnerabilities", [])) if secondary_result["parsed"] else 0,
            "result": secondary_result["parsed"],
        },
        "total_input_tokens": primary_result["input_tokens"] + secondary_result["input_tokens"],
        "total_output_tokens": primary_result["output_tokens"] + secondary_result["output_tokens"],
        "total_response_time_sec": primary_result["response_time_sec"] + secondary_result["response_time_sec"],
    }

    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"test3_two_phase_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(combined_log, f, ensure_ascii=False, indent=2)
    print(f"  📁 통합 로그 저장: {log_path}")

    # 통합 요약
    total_vulns = combined_log["phase1"]["vuln_count"] + combined_log["phase2"]["vuln_count"]
    print(f"\n  📊 통합 요약: Phase1 {combined_log['phase1']['vuln_count']}개 + Phase2 {combined_log['phase2']['vuln_count']}개 = 총 {total_vulns}개")
    print(f"  📊 총 토큰: Input {combined_log['total_input_tokens']} + Output {combined_log['total_output_tokens']}")
    print(f"  📊 총 시간: {combined_log['total_response_time_sec']}초")

    return combined_log


# ──────────────────────────────────────────────────────────
# Test 4: Confidence Score + Source 태깅
# ──────────────────────────────────────────────────────────
def run_test4():
    print("\n" + "🔴" * 35)
    print("  Test 4: Confidence Score + Source 태깅")
    print("🔴" * 35)

    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")
    doc3 = load_doc("iam_privesc_by_key_rotation")

    retrieved_context = f"""[문서 1 - vulnerable_lambda]
{doc1}

[문서 2 - eventbridge_target]
{doc2}

[문서 3 - iam_privesc_by_key_rotation]
{doc3}"""

    prompt = f"""
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 단순한 설정 오류 나열이 아니라, 현실적인 공격자가 실제로 악용 가능한 권한 조합과 신뢰 경계 붕괴 시나리오를 논리적으로 증명한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

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

[Confidence Score 산출 기준]
각 취약점에 대해 아래 기준으로 confidence 점수를 부여하라:
- 0.9~1.0: 확실히 재현 가능 (필요 권한이 모두 존재, 공격 경로 완전 증명)
- 0.7~0.9: 높은 확률 (대부분 조건 충족, 일부 환경 의존적)
- 0.5~0.7: 가능성 있음 (일부 권한 있으나 MFA/SourceIp 등 미확인)
- 0.3~0.5: 낮은 가능성 (핵심 권한 일부 누락)
- 0.0~0.3: 재현 불가 (필수 권한/리소스 없음)

[Source 태깅]
각 취약점의 source 필드에 출처를 명시하라:
- "rag_doc_1": 문서 1(vulnerable_lambda)에서 파생
- "rag_doc_2": 문서 2(eventbridge_target)에서 파생
- "rag_doc_3": 문서 3(iam_privesc_by_key_rotation)에서 파생
- "zero_base": RAG 문서와 무관하게 자체 발견

출력 형식
아래 스키마의 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "source": "rag_doc_1|rag_doc_2|rag_doc_3|zero_base",
            "confidence": 0.0,
            "confidence_reason": "점수 산출 근거"
        }}}}
    ]
}}}}
"""

    result = call_llm(prompt)
    context_docs = ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"]
    print_result("Test 4 (Confidence)", result, context_docs)

    # Confidence 분석
    if result["parsed"]:
        vulns = result["parsed"].get("vulnerabilities", [])
        print(f"\n  📊 Confidence 분석:")
        for v in vulns:
            conf = v.get("confidence", "N/A")
            src = v.get("source", "N/A")
            reason = v.get("confidence_reason", "N/A")
            title = v.get("title", "N/A")
            print(f"    [{src}] confidence={conf} | {title}")
            print(f"           근거: {reason}")
        
        # 자동 필터링 시뮬레이션
        high_conf = [v for v in vulns if isinstance(v.get("confidence"), (int, float)) and v["confidence"] >= 0.7]
        low_conf = [v for v in vulns if isinstance(v.get("confidence"), (int, float)) and v["confidence"] < 0.7]
        print(f"\n  📊 필터링 결과 (confidence >= 0.7):")
        print(f"    통과: {len(high_conf)}개 / 제외: {len(low_conf)}개")

    return save_log("test4_confidence", result, context_docs)


# ──────────────────────────────────────────────────────────
# Test 5: Chain-of-Verification (목록화 → 개별 검증)
# ──────────────────────────────────────────────────────────
def run_test5():
    print("\n" + "🟣" * 35)
    print("  Test 5: Chain-of-Verification (목록화 → 개별 검증)")
    print("🟣" * 35)

    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")
    doc3 = load_doc("iam_privesc_by_key_rotation")

    retrieved_context = f"""[문서 1 - vulnerable_lambda]
{doc1}

[문서 2 - eventbridge_target]
{doc2}

[문서 3 - iam_privesc_by_key_rotation]
{doc3}"""

    # ── Phase 1: 취약점 목록화 (Recall 우선) ──
    print("\n  ── Phase 1: 취약점 후보 목록화 (Recall 우선) ──")
    listing_prompt = f"""
역할: 너는 클라우드 보안 아키텍트이다.
목표: 아래 인프라에서 가능한 모든 공격 시나리오와 취약점을 빠짐없이 목록화한다.
이 단계에서는 정확성보다 포괄성(Recall)을 우선시한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[지침]
1. RAG 문서의 시나리오가 재현 가능한지 초벌 확인하고 후보로 등록하라.
2. RAG에 없는 추가 취약점도 가능성이 있으면 모두 후보로 등록하라.
3. 이 단계에서는 오탐 제거를 하지 않는다. 의심되면 일단 포함하라.

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트 금지.

스키마
{{{{
    "candidates": [
        {{{{
            "id": 1,
            "title": "취약점 제목",
            "attack_summary": "공격 시나리오 요약 (1~2문장)",
            "required_permissions": ["iam:CreateAccessKey", "events:PutRule"],
            "source": "rag_doc_1|rag_doc_2|rag_doc_3|zero_base"
        }}}}
    ]
}}}}
"""

    phase1_result = call_llm(listing_prompt)
    print_result("Test 5 - Phase 1 (목록화)", phase1_result, ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"])

    # Phase 1 결과 추출
    candidates_text = "없음"
    if phase1_result["parsed"]:
        candidates = phase1_result["parsed"].get("candidates", [])
        candidates_text = json.dumps(candidates, ensure_ascii=False, indent=2)
        print(f"\n  📋 후보 수: {len(candidates)}개")
    else:
        # JSON 파싱 실패 시 raw text 전달
        candidates_text = phase1_result["raw_text"]

    # ── Phase 2: 개별 검증 (Precision 우선) ──
    print("\n  ── Phase 2: 개별 검증 (Precision 우선) ──")
    verification_prompt = f"""
역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 취약점 후보들 각각에 대해, 입력 인프라에서 실제로 재현 가능한지 엄밀하게 검증한다.

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

검증 대상 후보 목록:
{candidates_text}

[검증 기준 (반드시 준수)]
1. 후보의 required_permissions가 인프라 내 실제 존재하는지 하나하나 대조하라.
2. 공격 경로의 각 단계가 연결 가능한지 증명하라.
3. MFA, Condition, SourceIp 등 방어 조건이 공격을 차단하는지 확인하라.
4. 재현 불가능한 후보는 결과에 포함하되 "verified": false와 사유를 명시하라.

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow/Deny/SCP/Boundary 모두 대조하여 실제 유효 권한 계산.
2. **[Identity vs Resource-based Policy Interaction]**: 정책 상호작용 분석.
3. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole 연쇄 경로 시뮬레이션.
4. **[False Positive Filtering]**: 제어 조건 검토하여 오탐 제거.

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트 금지.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "verified": true,
            "rejection_reason": null
        }}}}
    ]
}}}}
"""

    phase2_result = call_llm(verification_prompt)
    print_result("Test 5 - Phase 2 (검증)", phase2_result, ["개별 검증"])

    # 통합 로그
    combined_log = {
        "test_id": "test5_cove",
        "timestamp": datetime.now().isoformat(),
        "context_docs": ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"],
        "phase1_listing": {
            "input_tokens": phase1_result["input_tokens"],
            "output_tokens": phase1_result["output_tokens"],
            "response_time_sec": phase1_result["response_time_sec"],
            "finish_reason": phase1_result["finish_reason"],
            "truncated": phase1_result["truncated"],
            "candidate_count": len(phase1_result["parsed"].get("candidates", [])) if phase1_result["parsed"] else 0,
            "result": phase1_result["parsed"],
        },
        "phase2_verification": {
            "input_tokens": phase2_result["input_tokens"],
            "output_tokens": phase2_result["output_tokens"],
            "response_time_sec": phase2_result["response_time_sec"],
            "finish_reason": phase2_result["finish_reason"],
            "truncated": phase2_result["truncated"],
            "vuln_count": len(phase2_result["parsed"].get("vulnerabilities", [])) if phase2_result["parsed"] else 0,
            "result": phase2_result["parsed"],
        },
        "total_input_tokens": phase1_result["input_tokens"] + phase2_result["input_tokens"],
        "total_output_tokens": phase1_result["output_tokens"] + phase2_result["output_tokens"],
        "total_response_time_sec": phase1_result["response_time_sec"] + phase2_result["response_time_sec"],
    }

    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"test5_cove_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(combined_log, f, ensure_ascii=False, indent=2)
    print(f"  📁 통합 로그 저장: {log_path}")

    # 검증 통과/실패 요약
    if phase2_result["parsed"]:
        vulns = phase2_result["parsed"].get("vulnerabilities", [])
        verified = [v for v in vulns if v.get("verified", True) is True]
        rejected = [v for v in vulns if v.get("verified", True) is False]
        print(f"\n  📊 CoVe 결과: 검증 통과 {len(verified)}개 / 거부 {len(rejected)}개")
        for r in rejected:
            print(f"    ❌ {r.get('title', 'N/A')} — 사유: {r.get('rejection_reason', 'N/A')}")

    return combined_log


# ──────────────────────────────────────────────────────────
# Test 6: Confidence+거부사유 Phase 1 → Secondary Phase 2
#   6a: Phase 1에서 "RAG에 없는 추가 취약점 탐색 금지" 포함
#   6b: Phase 1에서 해당 제한 제거 (자유 탐지 허용)
#   num_docs=3 or 4 로 문서 수 조절
# ──────────────────────────────────────────────────────────
def _build_test6_context(num_docs):
    """문서 로딩 + retrieved_context 조립"""
    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")
    doc3 = load_doc("iam_privesc_by_key_rotation")

    ctx = f"""[문서 1 - vulnerable_lambda (유사도: 0.8014)]
{doc1}

[문서 2 - eventbridge_target (유사도: 0.7964)]
{doc2}

[문서 3 - iam_privesc_by_key_rotation (유사도: 0.7200)]
{doc3}"""

    source_tags = """- "rag_doc_1": 문서 1(vulnerable_lambda)에서 파생
- "rag_doc_2": 문서 2(eventbridge_target)에서 파생
- "rag_doc_3": 문서 3(iam_privesc_by_key_rotation)에서 파생"""

    doc_names = ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"]

    if num_docs >= 4:
        doc4 = load_doc("lambda_privesc")
        ctx += f"""

[문서 4 - lambda_privesc (유사도: 추정 ~0.70)]
{doc4}"""
        source_tags += '\n- "rag_doc_4": 문서 4(lambda_privesc)에서 파생'
        doc_names.append("lambda_privesc")

    return ctx, source_tags, doc_names


def _run_test6_variant(variant, num_docs, retrieved_context, source_tags, doc_names):
    """Test 6 Phase 1 + Phase 2 실행 (variant='a' or 'b')"""
    restrict = (variant == "a")
    label = f"6{variant}_{num_docs}docs"
    emoji = "🔵" if variant == "a" else "🟢"

    print(f"\n{emoji * 35}")
    print(f"  Test {label}: {'제한 O' if restrict else '제한 X'} + {num_docs}문서")
    print(f"{emoji * 35}")

    # ── Phase 1 프롬프트 ──
    restriction_line = ""
    if restrict:
        restriction_line = "4. 이 단계에서는 RAG에 없는 추가 취약점을 탐색하지 마라.\n"
    else:
        restriction_line = "4. RAG 문서의 시나리오 검증과 함께, RAG에 없더라도 인프라에서 발견되는 추가 취약점도 함께 보고하라.\n"

    # Source 태깅 스키마 (4문서일 때 rag_doc_4 추가)
    source_enum = "rag_doc_1|rag_doc_2|rag_doc_3"
    if num_docs >= 4:
        source_enum = "rag_doc_1|rag_doc_2|rag_doc_3|rag_doc_4"

    phase1_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 RAG 문서들의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하고, 각 문서에 대해 confidence score와 출처를 명시한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[분석 지침 (반드시 준수)]
1. 각 RAG 문서의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하라.
2. 재현 가능한 시나리오는 vulnerabilities에 포함하고 confidence score를 부여하라.
3. 재현 불가능한 시나리오는 rejected_scenarios에 포함하고 구체적 거부 사유를 명시하라.
{restriction_line}
[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow/Deny/SCP/Boundary 모두 대조하여 실제 유효 권한 계산.
2. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole, Lambda 실행 역할 등을 포함한 연쇄·간접 공격 경로를 시뮬레이션하라.
3. **[간접 권한 주의]**: 사용자가 직접 보유하지 않더라도 Lambda 실행 역할, AssumeRole 체인 등 간접 경로를 통해 획득 가능한 권한을 반드시 고려하라.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.

[Confidence Score 산출 기준]
- 0.9~1.0: 확실히 재현 가능 (필요 권한이 모두 존재, 공격 경로 완전 증명)
- 0.7~0.9: 높은 확률 (대부분 조건 충족, 일부 환경 의존적)
- 0.5~0.7: 가능성 있음 (일부 권한 있으나 MFA/SourceIp 등 미확인)
- 0.3~0.5: 낮은 가능성 (핵심 권한 일부 누락)
- 0.0~0.3: 재현 불가 (필수 권한/리소스 없음)

[Source 태깅]
{source_tags}

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "source": "{source_enum}",
            "confidence": 0.0,
            "confidence_reason": "점수 산출 근거"
        }}}}
    ],
    "rejected_scenarios": [
        {{{{
            "source": "{source_enum}",
            "doc_title": "문서 시나리오 제목",
            "rejection_reason": "거부 사유 (어떤 권한이 없어서 재현 불가능한지 구체적으로)",
            "missing_permissions": ["iam:InvokeFunction"]
        }}}}
    ]
}}}}
"""

    print(f"\n  ── Phase 1: RAG 검증 + Confidence + 거부사유 ({'제한 O' if restrict else '제한 X'}) ──")
    phase1_result = call_llm(phase1_prompt)
    print_result(f"Test {label} - Phase 1", phase1_result, doc_names)

    # 거부 시나리오 출력
    if phase1_result["parsed"]:
        rejected = phase1_result["parsed"].get("rejected_scenarios", [])
        if rejected:
            print(f"\n  📊 거부된 RAG 시나리오: {len(rejected)}개")
            for r in rejected:
                src = r.get("source", "?")
                title = r.get("doc_title", "N/A")
                reason = r.get("rejection_reason", "N/A")
                missing = r.get("missing_permissions", [])
                print(f"    ❌ [{src}] {title}")
                print(f"       사유: {reason}")
                if missing:
                    print(f"       누락 권한: {', '.join(missing)}")

        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        if vulns:
            print(f"\n  📊 검증 통과: {len(vulns)}개")
            for v in vulns:
                src = v.get("source", "?")
                conf = v.get("confidence", "?")
                title = v.get("title", "N/A")
                print(f"    ✅ [{src}] conf={conf} | {title}")

    # Phase 2: Secondary
    primary_summary = "없음"
    if phase1_result["parsed"]:
        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        titles = [v.get("title", "") for v in vulns]
        primary_summary = "\n".join([f"- {t}" for t in titles]) if titles else "없음"

    print(f"\n  ── Phase 2: Secondary (Zero-Base 확장 탐지) ──")
    secondary_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 인프라에서 아직 식별되지 않은 추가 취약점을 탐색한다.

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

이미 식별된 취약점 (제외 대상 - 중복 보고 금지):
{primary_summary}

[분석 지침 (반드시 준수)]
1. 위에 이미 식별된 취약점은 중복 보고하지 마라.
2. 클라우드 보안 지식(OWASP, AWS Best Practices)을 총동원하여 인프라 전체를 스캔하라.
3. IAM 권한 오남용, 리소스 노출, 암호화 미비 등 치명적 취약점을 식별하여 보고하라.
4. sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로(Multi-hop Attack)를 시뮬레이션하라.
5. 간접 경로(Lambda 역할, EventBridge 등)를 통한 권한 획득 가능성도 고려하라.

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0
        }}}}
    ]
}}}}
"""
    secondary_result = call_llm(secondary_prompt)
    print_result(f"Test {label} - Phase 2 (Secondary)", secondary_result, ["zero_base_only"])

    # 통합 로그
    combined_log = {
        "test_id": f"test6{variant}_{num_docs}docs",
        "variant": f"6{variant}",
        "restriction": restrict,
        "num_docs": num_docs,
        "timestamp": datetime.now().isoformat(),
        "context_docs": doc_names,
        "phase1": {
            "input_tokens": phase1_result["input_tokens"],
            "output_tokens": phase1_result["output_tokens"],
            "response_time_sec": phase1_result["response_time_sec"],
            "finish_reason": phase1_result["finish_reason"],
            "truncated": phase1_result["truncated"],
            "vuln_count": len(phase1_result["parsed"].get("vulnerabilities", [])) if phase1_result["parsed"] else 0,
            "rejected_count": len(phase1_result["parsed"].get("rejected_scenarios", [])) if phase1_result["parsed"] else 0,
            "result": phase1_result["parsed"],
        },
        "phase2": {
            "input_tokens": secondary_result["input_tokens"],
            "output_tokens": secondary_result["output_tokens"],
            "response_time_sec": secondary_result["response_time_sec"],
            "finish_reason": secondary_result["finish_reason"],
            "truncated": secondary_result["truncated"],
            "vuln_count": len(secondary_result["parsed"].get("vulnerabilities", [])) if secondary_result["parsed"] else 0,
            "result": secondary_result["parsed"],
        },
        "total_input_tokens": phase1_result["input_tokens"] + secondary_result["input_tokens"],
        "total_output_tokens": phase1_result["output_tokens"] + secondary_result["output_tokens"],
        "total_response_time_sec": phase1_result["response_time_sec"] + secondary_result["response_time_sec"],
    }

    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"test6{variant}_{num_docs}docs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(combined_log, f, ensure_ascii=False, indent=2)
    print(f"  📁 로그 저장: {log_path}")

    total_vulns = combined_log["phase1"]["vuln_count"] + combined_log["phase2"]["vuln_count"]
    print(f"\n  📊 [{label}] Phase1 {combined_log['phase1']['vuln_count']}개(검증) + {combined_log['phase1']['rejected_count']}개(거부) + Phase2 {combined_log['phase2']['vuln_count']}개(추가) = 총 {total_vulns}개")

    return combined_log


def _run_test6_variant_c(num_docs):
    """Test 6 variant c: 제한O + 패턴 매칭 허용
    원문 시나리오와 정확히 일치하지 않더라도 동일 취약점 패턴의 변형 경로가
    인프라에 존재하면 검증 통과로 처리.
    """
    retrieved_context, source_tags, doc_names = _build_test6_context(num_docs)
    label = f"6c_{num_docs}docs"
    emoji = "🟡"

    print(f"\n{emoji * 35}")
    print(f"  Test {label}: 제한 O + 패턴매칭 + {num_docs}문서")
    print(f"{emoji * 35}")

    # Source 태깅 스키마
    source_enum = "rag_doc_1|rag_doc_2|rag_doc_3"
    if num_docs >= 4:
        source_enum = "rag_doc_1|rag_doc_2|rag_doc_3|rag_doc_4"

    phase1_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 RAG 문서들의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하고, 각 문서에 대해 confidence score와 출처를 명시한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[분석 지침 (반드시 준수)]
1. 각 RAG 문서의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하라.
2. 재현 가능한 시나리오는 vulnerabilities에 포함하고 confidence score를 부여하라.
3. 재현 불가능한 시나리오는 rejected_scenarios에 포함하고 구체적 거부 사유를 명시하라.
4. **[패턴 매칭 허용]**: RAG 문서의 원래 시나리오가 정확히 일치하지 않더라도, 동일한 취약점 패턴(예: AccessKey 생성을 통한 자격증명 탈취, AssumeRole 체인을 통한 권한 상승 등)의 **변형 경로**가 인프라에 존재하면 검증 통과로 처리하라. 이 경우 confidence_reason에 "원문 시나리오 변형: [변형 내용]"을 명시하라.

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow/Deny/SCP/Boundary 모두 대조하여 실제 유효 권한 계산.
2. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole, Lambda 실행 역할 등을 포함한 연쇄·간접 공격 경로를 시뮬레이션하라.
3. **[간접 권한 주의]**: 사용자가 직접 보유하지 않더라도 Lambda 실행 역할, AssumeRole 체인 등 간접 경로를 통해 획득 가능한 권한을 반드시 고려하라.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.

[Confidence Score 산출 기준]
- 0.9~1.0: 확실히 재현 가능 (필요 권한이 모두 존재, 공격 경로 완전 증명)
- 0.7~0.9: 높은 확률 (대부분 조건 충족, 일부 환경 의존적)
- 0.5~0.7: 가능성 있음 (일부 권한 있으나 MFA/SourceIp 등 미확인)
- 0.3~0.5: 낮은 가능성 (핵심 권한 일부 누락)
- 0.0~0.3: 재현 불가 (필수 권한/리소스 없음)

[Source 태깅]
{source_tags}

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "source": "{source_enum}",
            "confidence": 0.0,
            "confidence_reason": "점수 산출 근거"
        }}}}}}
    ],
    "rejected_scenarios": [
        {{{{{{
            "source": "{source_enum}",
            "doc_title": "문서 시나리오 제목",
            "rejection_reason": "거부 사유 (어떤 권한이 없어서 재현 불가능한지 구체적으로)",
            "missing_permissions": ["iam:InvokeFunction"]
        }}}}}}
    ]
}}}}}}
"""

    print(f"\n  ── Phase 1: RAG 검증 + Confidence + 거부사유 (제한 O + 패턴매칭) ──")
    phase1_result = call_llm(phase1_prompt)
    print_result(f"Test {label} - Phase 1", phase1_result, doc_names)

    # 거부 시나리오 출력
    if phase1_result["parsed"]:
        rejected = phase1_result["parsed"].get("rejected_scenarios", [])
        if rejected:
            print(f"\n  📊 거부된 RAG 시나리오: {len(rejected)}개")
            for r in rejected:
                src = r.get("source", "?")
                title = r.get("doc_title", "N/A")
                reason = r.get("rejection_reason", "N/A")
                missing = r.get("missing_permissions", [])
                print(f"    ❌ [{src}] {title}")
                print(f"       사유: {reason}")
                if missing:
                    print(f"       누락 권한: {', '.join(missing)}")

        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        if vulns:
            print(f"\n  📊 검증 통과: {len(vulns)}개")
            for v in vulns:
                src = v.get("source", "?")
                conf = v.get("confidence", "?")
                title = v.get("title", "N/A")
                cr = v.get("confidence_reason", "")
                is_variant = "원문 시나리오 변형" in cr
                marker = " 🔄(변형)" if is_variant else ""
                print(f"    ✅ [{src}] conf={conf} | {title}{marker}")
                if is_variant:
                    print(f"       변형 근거: {cr}")

    # Phase 2: Secondary
    primary_summary = "없음"
    if phase1_result["parsed"]:
        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        titles = [v.get("title", "") for v in vulns]
        primary_summary = "\n".join([f"- {t}" for t in titles]) if titles else "없음"

    print(f"\n  ── Phase 2: Secondary (Zero-Base 확장 탐지) ──")
    secondary_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 인프라에서 아직 식별되지 않은 추가 취약점을 탐색한다.

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

이미 식별된 취약점 (제외 대상 - 중복 보고 금지):
{primary_summary}

[분석 지침 (반드시 준수)]
1. 위에 이미 식별된 취약점은 중복 보고하지 마라.
2. 클라우드 보안 지식(OWASP, AWS Best Practices)을 총동원하여 인프라 전체를 스캔하라.
3. IAM 권한 오남용, 리소스 노출, 암호화 미비 등 치명적 취약점을 식별하여 보고하라.
4. sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로(Multi-hop Attack)를 시뮬레이션하라.
5. 간접 경로(Lambda 역할, EventBridge 등)를 통한 권한 획득 가능성도 고려하라.

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0
        }}}}}}
    ]
}}}}}}
"""
    secondary_result = call_llm(secondary_prompt)
    print_result(f"Test {label} - Phase 2 (Secondary)", secondary_result, ["zero_base_only"])

    # 통합 로그
    combined_log = {
        "test_id": f"test6c_{num_docs}docs",
        "variant": "6c",
        "restriction": "pattern_match",
        "num_docs": num_docs,
        "timestamp": datetime.now().isoformat(),
        "context_docs": doc_names,
        "phase1": {
            "input_tokens": phase1_result["input_tokens"],
            "output_tokens": phase1_result["output_tokens"],
            "response_time_sec": phase1_result["response_time_sec"],
            "finish_reason": phase1_result["finish_reason"],
            "truncated": phase1_result["truncated"],
            "vuln_count": len(phase1_result["parsed"].get("vulnerabilities", [])) if phase1_result["parsed"] else 0,
            "rejected_count": len(phase1_result["parsed"].get("rejected_scenarios", [])) if phase1_result["parsed"] else 0,
            "result": phase1_result["parsed"],
        },
        "phase2": {
            "input_tokens": secondary_result["input_tokens"],
            "output_tokens": secondary_result["output_tokens"],
            "response_time_sec": secondary_result["response_time_sec"],
            "finish_reason": secondary_result["finish_reason"],
            "truncated": secondary_result["truncated"],
            "vuln_count": len(secondary_result["parsed"].get("vulnerabilities", [])) if secondary_result["parsed"] else 0,
            "result": secondary_result["parsed"],
        },
        "total_input_tokens": phase1_result["input_tokens"] + secondary_result["input_tokens"],
        "total_output_tokens": phase1_result["output_tokens"] + secondary_result["output_tokens"],
        "total_response_time_sec": phase1_result["response_time_sec"] + secondary_result["response_time_sec"],
    }

    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"test6c_{num_docs}docs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(combined_log, f, ensure_ascii=False, indent=2)
    print(f"  📁 로그 저장: {log_path}")

    total_vulns = combined_log["phase1"]["vuln_count"] + combined_log["phase2"]["vuln_count"]
    print(f"\n  📊 [{label}] Phase1 {combined_log['phase1']['vuln_count']}개(검증) + {combined_log['phase1']['rejected_count']}개(거부) + Phase2 {combined_log['phase2']['vuln_count']}개(추가) = 총 {total_vulns}개")

    return combined_log


def run_test6_1():
    """Test 6-1: 제한O + 3문서"""
    ctx, tags, names = _build_test6_context(3)
    return _run_test6_variant("a", 3, ctx, tags, names)


def run_test6_2():
    """Test 6-2: 제한O + 4문서"""
    ctx, tags, names = _build_test6_context(4)
    return _run_test6_variant("a", 4, ctx, tags, names)


def run_test6_3():
    """Test 6-3: 제한X + 3문서"""
    ctx, tags, names = _build_test6_context(3)
    return _run_test6_variant("b", 3, ctx, tags, names)


def run_test6_4():
    """Test 6-4: 제한X + 4문서"""
    ctx, tags, names = _build_test6_context(4)
    return _run_test6_variant("b", 4, ctx, tags, names)


def run_test6_5():
    """Test 6-5: 제한O + 패턴매칭 + 3문서"""
    return _run_test6_variant_c(3)


def _run_test6_variant_d(num_docs):
    """Test 6 variant d: 제한O + 패턴매칭 + Phase 2 제외정보 강화
    Phase 1은 variant_c와 동일 (패턴매칭 허용).
    Phase 2에서 title뿐 아니라 attackPath + 관련 리소스 + 핵심 권한을
    상세히 전달하여 중복 보고를 방지.
    """
    retrieved_context, source_tags, doc_names = _build_test6_context(num_docs)
    label = f"6d_{num_docs}docs"
    emoji = "🟠"

    print(f"\n{emoji * 35}")
    print(f"  Test {label}: 제한 O + 패턴매칭 + P2강화 + {num_docs}문서")
    print(f"{emoji * 35}")

    # Source 태깅 스키마
    source_enum = "rag_doc_1|rag_doc_2|rag_doc_3"
    if num_docs >= 4:
        source_enum = "rag_doc_1|rag_doc_2|rag_doc_3|rag_doc_4"

    # ── Phase 1: variant_c와 동일한 프롬프트 (패턴매칭 허용) ──
    phase1_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 RAG 문서들의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하고, 각 문서에 대해 confidence score와 출처를 명시한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[분석 지침 (반드시 준수)]
1. 각 RAG 문서의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하라.
2. 재현 가능한 시나리오는 vulnerabilities에 포함하고 confidence score를 부여하라.
3. 재현 불가능한 시나리오는 rejected_scenarios에 포함하고 구체적 거부 사유를 명시하라.
4. **[패턴 매칭 허용]**: RAG 문서의 원래 시나리오가 정확히 일치하지 않더라도, 동일한 취약점 패턴(예: AccessKey 생성을 통한 자격증명 탈취, AssumeRole 체인을 통한 권한 상승 등)의 **변형 경로**가 인프라에 존재하면 검증 통과로 처리하라. 이 경우 confidence_reason에 "원문 시나리오 변형: [변형 내용]"을 명시하라.

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow/Deny/SCP/Boundary 모두 대조하여 실제 유효 권한 계산.
2. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole, Lambda 실행 역할 등을 포함한 연쇄·간접 공격 경로를 시뮬레이션하라.
3. **[간접 권한 주의]**: 사용자가 직접 보유하지 않더라도 Lambda 실행 역할, AssumeRole 체인 등 간접 경로를 통해 획득 가능한 권한을 반드시 고려하라.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.

[Confidence Score 산출 기준]
- 0.9~1.0: 확실히 재현 가능 (필요 권한이 모두 존재, 공격 경로 완전 증명)
- 0.7~0.9: 높은 확률 (대부분 조건 충족, 일부 환경 의존적)
- 0.5~0.7: 가능성 있음 (일부 권한 있으나 MFA/SourceIp 등 미확인)
- 0.3~0.5: 낮은 가능성 (핵심 권한 일부 누락)
- 0.0~0.3: 재현 불가 (필수 권한/리소스 없음)

[Source 태깅]
{source_tags}

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "source": "{source_enum}",
            "confidence": 0.0,
            "confidence_reason": "점수 산출 근거"
        }}}}}}
    ],
    "rejected_scenarios": [
        {{{{{{
            "source": "{source_enum}",
            "doc_title": "문서 시나리오 제목",
            "rejection_reason": "거부 사유 (어떤 권한이 없어서 재현 불가능한지 구체적으로)",
            "missing_permissions": ["iam:InvokeFunction"]
        }}}}}}
    ]
}}}}}}
"""

    print(f"\n  ── Phase 1: RAG 검증 + Confidence + 거부사유 (제한 O + 패턴매칭) ──")
    phase1_result = call_llm(phase1_prompt)
    print_result(f"Test {label} - Phase 1", phase1_result, doc_names)

    # 거부 시나리오 출력
    if phase1_result["parsed"]:
        rejected = phase1_result["parsed"].get("rejected_scenarios", [])
        if rejected:
            print(f"\n  📊 거부된 RAG 시나리오: {len(rejected)}개")
            for r in rejected:
                src = r.get("source", "?")
                title = r.get("doc_title", "N/A")
                reason = r.get("rejection_reason", "N/A")
                missing = r.get("missing_permissions", [])
                print(f"    ❌ [{src}] {title}")
                print(f"       사유: {reason}")
                if missing:
                    print(f"       누락 권한: {', '.join(missing)}")

        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        if vulns:
            print(f"\n  📊 검증 통과: {len(vulns)}개")
            for v in vulns:
                src = v.get("source", "?")
                conf = v.get("confidence", "?")
                title = v.get("title", "N/A")
                cr = v.get("confidence_reason", "")
                is_variant = "원문 시나리오 변형" in cr
                marker = " 🔄(변형)" if is_variant else ""
                print(f"    ✅ [{src}] conf={conf} | {title}{marker}")
                if is_variant:
                    print(f"       변형 근거: {cr}")

    # ── Phase 2: 제외 정보 강화 (attackPath + 리소스 + 핵심 권한) ──
    primary_exclusion = "없음"
    if phase1_result["parsed"]:
        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        exclusion_items = []
        for i, v in enumerate(vulns, 1):
            attack_path = v.get("attackPath", [])
            path_str = " → ".join(attack_path) if attack_path else "경로 없음"
            desc = v.get("description", "")
            title = v.get("title", "")
            source = v.get("source", "")
            # 공격 경로에서 핵심 리소스/권한 추출 (텍스트 기반)
            item = (f"[{i}] {title}\n"
                    f"    출처: {source}\n"
                    f"    공격경로: {path_str}\n"
                    f"    설명: {desc}")
            exclusion_items.append(item)
        primary_exclusion = "\n".join(exclusion_items) if exclusion_items else "없음"

    print(f"\n  ── Phase 2: Secondary (Zero-Base 확장 탐지, 제외정보 강화) ──")
    secondary_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 인프라에서 아직 식별되지 않은 **완전히 새로운** 추가 취약점을 탐색한다.

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

이미 식별된 취약점 (제외 대상 - 아래 시나리오와 동일하거나 부분적으로 겹치는 공격 경로는 중복으로 간주하여 보고하지 마라):
{primary_exclusion}

[중복 판정 기준 (반드시 준수)]
1. 위 제외 목록의 공격경로에 포함된 **동일 리소스**(IAM 사용자, 역할, Lambda, EventBridge 등)를 사용하는 취약점은 중복이다.
2. 제외 목록의 공격경로와 **동일한 권한 체인**(예: CreateAccessKey→AssumeRole, PutRule→Lambda 트리거)을 사용하는 취약점은 중복이다.
3. 제외 목록 취약점의 **영향(impact)** 부분만 분리하여 별도 취약점으로 보고하지 마라 (예: "Secrets Manager 미암호화"는 이미 Secrets Manager 탈취 경로에 포함됨).

[분석 지침 (반드시 준수)]
1. 위의 중복 판정 기준을 먼저 검토한 후, 확실히 새로운 취약점만 보고하라.
2. 클라우드 보안 지식(OWASP, AWS Best Practices)을 총동원하여 인프라 전체를 스캔하라.
3. IAM 권한 오남용, 리소스 노출, 암호화 미비 등 치명적 취약점을 식별하여 보고하라.
4. sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로(Multi-hop Attack)를 시뮬레이션하라.
5. 간접 경로(Lambda 역할, EventBridge 등)를 통한 권한 획득 가능성도 고려하라.

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0
        }}}}}}
    ]
}}}}}}
"""
    secondary_result = call_llm(secondary_prompt)
    print_result(f"Test {label} - Phase 2 (Secondary, 제외강화)", secondary_result, ["zero_base_only"])

    # 통합 로그
    combined_log = {
        "test_id": f"test6d_{num_docs}docs",
        "variant": "6d",
        "restriction": "pattern_match+enhanced_exclusion",
        "num_docs": num_docs,
        "timestamp": datetime.now().isoformat(),
        "context_docs": doc_names,
        "phase1": {
            "input_tokens": phase1_result["input_tokens"],
            "output_tokens": phase1_result["output_tokens"],
            "response_time_sec": phase1_result["response_time_sec"],
            "finish_reason": phase1_result["finish_reason"],
            "truncated": phase1_result["truncated"],
            "vuln_count": len(phase1_result["parsed"].get("vulnerabilities", [])) if phase1_result["parsed"] else 0,
            "rejected_count": len(phase1_result["parsed"].get("rejected_scenarios", [])) if phase1_result["parsed"] else 0,
            "result": phase1_result["parsed"],
        },
        "phase2": {
            "input_tokens": secondary_result["input_tokens"],
            "output_tokens": secondary_result["output_tokens"],
            "response_time_sec": secondary_result["response_time_sec"],
            "finish_reason": secondary_result["finish_reason"],
            "truncated": secondary_result["truncated"],
            "vuln_count": len(secondary_result["parsed"].get("vulnerabilities", [])) if secondary_result["parsed"] else 0,
            "result": secondary_result["parsed"],
        },
        "total_input_tokens": phase1_result["input_tokens"] + secondary_result["input_tokens"],
        "total_output_tokens": phase1_result["output_tokens"] + secondary_result["output_tokens"],
        "total_response_time_sec": phase1_result["response_time_sec"] + secondary_result["response_time_sec"],
    }

    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"test6d_{num_docs}docs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(combined_log, f, ensure_ascii=False, indent=2)
    print(f"  📁 로그 저장: {log_path}")

    total_vulns = combined_log["phase1"]["vuln_count"] + combined_log["phase2"]["vuln_count"]
    print(f"\n  📊 [{label}] Phase1 {combined_log['phase1']['vuln_count']}개(검증) + {combined_log['phase1']['rejected_count']}개(거부) + Phase2 {combined_log['phase2']['vuln_count']}개(추가) = 총 {total_vulns}개")

    return combined_log


def run_test6_6():
    """Test 6-6: 제한O + 패턴매칭 + P2제외강화 + 3문서"""
    return _run_test6_variant_d(3)


def _run_test6_variant_e(num_docs):
    """Test 6 variant e: variant_d에서 [중복 판정 기준] 제거
    Phase 2에 상세 제외 정보(attackPath+리소스)는 전달하되,
    명시적 중복 규칙 없이 LLM 자율 판단에 맡김.
    """
    retrieved_context, source_tags, doc_names = _build_test6_context(num_docs)
    label = f"6e_{num_docs}docs"
    emoji = "🟣"

    print(f"\n{emoji * 35}")
    print(f"  Test {label}: 제한 O + 패턴매칭 + P2제외(규칙X) + {num_docs}문서")
    print(f"{emoji * 35}")

    source_enum = "rag_doc_1|rag_doc_2|rag_doc_3"
    if num_docs >= 4:
        source_enum = "rag_doc_1|rag_doc_2|rag_doc_3|rag_doc_4"

    # Phase 1: variant_c/d와 동일 (패턴매칭 허용)
    phase1_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 RAG 문서들의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하고, 각 문서에 대해 confidence score와 출처를 명시한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[분석 지침 (반드시 준수)]
1. 각 RAG 문서의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하라.
2. 재현 가능한 시나리오는 vulnerabilities에 포함하고 confidence score를 부여하라.
3. 재현 불가능한 시나리오는 rejected_scenarios에 포함하고 구체적 거부 사유를 명시하라.
4. **[패턴 매칭 허용]**: RAG 문서의 원래 시나리오가 정확히 일치하지 않더라도, 동일한 취약점 패턴(예: AccessKey 생성을 통한 자격증명 탈취, AssumeRole 체인을 통한 권한 상승 등)의 **변형 경로**가 인프라에 존재하면 검증 통과로 처리하라. 이 경우 confidence_reason에 "원문 시나리오 변형: [변형 내용]"을 명시하라.

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow/Deny/SCP/Boundary 모두 대조하여 실제 유효 권한 계산.
2. **[Multi-hop Attack Simulation]**: sts:AssumeRole, iam:PassRole, Lambda 실행 역할 등을 포함한 연쇄·간접 공격 경로를 시뮬레이션하라.
3. **[간접 권한 주의]**: 사용자가 직접 보유하지 않더라도 Lambda 실행 역할, AssumeRole 체인 등 간접 경로를 통해 획득 가능한 권한을 반드시 고려하라.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토하여 실제 공격 불가능한 오탐을 제거하라.

[Confidence Score 산출 기준]
- 0.9~1.0: 확실히 재현 가능 (필요 권한이 모두 존재, 공격 경로 완전 증명)
- 0.7~0.9: 높은 확률 (대부분 조건 충족, 일부 환경 의존적)
- 0.5~0.7: 가능성 있음 (일부 권한 있으나 MFA/SourceIp 등 미확인)
- 0.3~0.5: 낮은 가능성 (핵심 권한 일부 누락)
- 0.0~0.3: 재현 불가 (필수 권한/리소스 없음)

[Source 태깅]
{source_tags}

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "source": "{source_enum}",
            "confidence": 0.0,
            "confidence_reason": "점수 산출 근거"
        }}}}}}
    ],
    "rejected_scenarios": [
        {{{{{{
            "source": "{source_enum}",
            "doc_title": "문서 시나리오 제목",
            "rejection_reason": "거부 사유 (어떤 권한이 없어서 재현 불가능한지 구체적으로)",
            "missing_permissions": ["iam:InvokeFunction"]
        }}}}}}
    ]
}}}}}}
"""

    print(f"\n  ── Phase 1: RAG 검증 + Confidence + 거부사유 (제한 O + 패턴매칭) ──")
    phase1_result = call_llm(phase1_prompt)
    print_result(f"Test {label} - Phase 1", phase1_result, doc_names)

    if phase1_result["parsed"]:
        rejected = phase1_result["parsed"].get("rejected_scenarios", [])
        if rejected:
            print(f"\n  📊 거부된 RAG 시나리오: {len(rejected)}개")
            for r in rejected:
                src = r.get("source", "?")
                title = r.get("doc_title", "N/A")
                reason = r.get("rejection_reason", "N/A")
                missing = r.get("missing_permissions", [])
                print(f"    ❌ [{src}] {title}")
                print(f"       사유: {reason}")
                if missing:
                    print(f"       누락 권한: {', '.join(missing)}")

        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        if vulns:
            print(f"\n  📊 검증 통과: {len(vulns)}개")
            for v in vulns:
                src = v.get("source", "?")
                conf = v.get("confidence", "?")
                title = v.get("title", "N/A")
                cr = v.get("confidence_reason", "")
                is_variant = "원문 시나리오 변형" in cr
                marker = " 🔄(변형)" if is_variant else ""
                print(f"    ✅ [{src}] conf={conf} | {title}{marker}")
                if is_variant:
                    print(f"       변형 근거: {cr}")

    # Phase 2: 상세 제외 정보 전달, 중복 규칙 없음
    primary_exclusion = "없음"
    if phase1_result["parsed"]:
        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        exclusion_items = []
        for i, v in enumerate(vulns, 1):
            attack_path = v.get("attackPath", [])
            path_str = " → ".join(attack_path) if attack_path else "경로 없음"
            desc = v.get("description", "")
            title = v.get("title", "")
            source = v.get("source", "")
            item = (f"[{i}] {title}\n"
                    f"    출처: {source}\n"
                    f"    공격경로: {path_str}\n"
                    f"    설명: {desc}")
            exclusion_items.append(item)
        primary_exclusion = "\n".join(exclusion_items) if exclusion_items else "없음"

    print(f"\n  ── Phase 2: Secondary (Zero-Base 확장 탐지, 제외정보O 규칙X) ──")
    secondary_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 인프라에서 아직 식별되지 않은 추가 취약점을 탐색한다.

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

이미 식별된 취약점 (제외 대상 - 중복 보고 금지):
{primary_exclusion}

[분석 지침 (반드시 준수)]
1. 위에 이미 식별된 취약점은 중복 보고하지 마라.
2. 클라우드 보안 지식(OWASP, AWS Best Practices)을 총동원하여 인프라 전체를 스캔하라.
3. IAM 권한 오남용, 리소스 노출, 암호화 미비 등 치명적 취약점을 식별하여 보고하라.
4. sts:AssumeRole, iam:PassRole 등을 포함한 연쇄 공격 경로(Multi-hop Attack)를 시뮬레이션하라.
5. 간접 경로(Lambda 역할, EventBridge 등)를 통한 권한 획득 가능성도 고려하라.

출력 형식: 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0
        }}}}}}
    ]
}}}}}}
"""
    secondary_result = call_llm(secondary_prompt)
    print_result(f"Test {label} - Phase 2 (Secondary, 제외O규칙X)", secondary_result, ["zero_base_only"])

    combined_log = {
        "test_id": f"test6e_{num_docs}docs",
        "variant": "6e",
        "restriction": "pattern_match+exclusion_no_rules",
        "num_docs": num_docs,
        "timestamp": datetime.now().isoformat(),
        "context_docs": doc_names,
        "phase1": {
            "input_tokens": phase1_result["input_tokens"],
            "output_tokens": phase1_result["output_tokens"],
            "response_time_sec": phase1_result["response_time_sec"],
            "finish_reason": phase1_result["finish_reason"],
            "truncated": phase1_result["truncated"],
            "vuln_count": len(phase1_result["parsed"].get("vulnerabilities", [])) if phase1_result["parsed"] else 0,
            "rejected_count": len(phase1_result["parsed"].get("rejected_scenarios", [])) if phase1_result["parsed"] else 0,
            "result": phase1_result["parsed"],
        },
        "phase2": {
            "input_tokens": secondary_result["input_tokens"],
            "output_tokens": secondary_result["output_tokens"],
            "response_time_sec": secondary_result["response_time_sec"],
            "finish_reason": secondary_result["finish_reason"],
            "truncated": secondary_result["truncated"],
            "vuln_count": len(secondary_result["parsed"].get("vulnerabilities", [])) if secondary_result["parsed"] else 0,
            "result": secondary_result["parsed"],
        },
        "total_input_tokens": phase1_result["input_tokens"] + secondary_result["input_tokens"],
        "total_output_tokens": phase1_result["output_tokens"] + secondary_result["output_tokens"],
        "total_response_time_sec": phase1_result["response_time_sec"] + secondary_result["response_time_sec"],
    }

    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"test6e_{num_docs}docs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(combined_log, f, ensure_ascii=False, indent=2)
    print(f"  📁 로그 저장: {log_path}")

    total_vulns = combined_log["phase1"]["vuln_count"] + combined_log["phase2"]["vuln_count"]
    print(f"\n  📊 [{label}] Phase1 {combined_log['phase1']['vuln_count']}개(검증) + {combined_log['phase1']['rejected_count']}개(거부) + Phase2 {combined_log['phase2']['vuln_count']}개(추가) = 총 {total_vulns}개")

    return combined_log


def run_test6_7():
    """Test 6-7: 제한O + 패턴매칭 + P2제외(규칙X) + 3문서"""
    return _run_test6_variant_e(3)


def run_test6_all():
    """Test 6 전체: 7가지 변형 모두 실행 후 비교"""
    results = {}
    for idx, (label, func) in enumerate([
        ("6-1 (제한O, 3문서)", run_test6_1),
        ("6-2 (제한O, 4문서)", run_test6_2),
        ("6-3 (제한X, 3문서)", run_test6_3),
        ("6-4 (제한X, 4문서)", run_test6_4),
        ("6-5 (제한O+패턴매칭, 3문서)", run_test6_5),
        ("6-6 (제한O+패턴매칭+P2강화, 3문서)", run_test6_6),
        ("6-7 (제한O+패턴매칭+P2제외(X), 3문서)", run_test6_7),
    ], 1):
        print(f"\n\n{'🔶' * 35}")
        print(f"  ▶ Test {label} 시작 ({idx}/7)")
        print(f"{'🔶' * 35}")
        try:
            results[f"test6_{idx}"] = func()
        except Exception as e:
            print(f"  ❌ {label} 실패: {e}")
            results[f"test6_{idx}"] = {"error": str(e)}

    # ── 7가지 비교 요약 ──
    print(f"\n\n{'=' * 90}")
    print("📊 Test 6 전체 비교 요약 (7가지 변형)")
    print(f"{'=' * 90}")
    print(f"  {'테스트':<22} {'제한':<16} {'문서':<4} {'P1검증':<6} {'P1거부':<6} {'P2추가':<6} {'총합':<6} {'토큰(합계)':<12} {'시간(초)':<8}")
    print(f"  {'─' * 90}")

    configs = [
        ("test6_1", "제한O", "3"),
        ("test6_2", "제한O", "4"),
        ("test6_3", "제한X", "3"),
        ("test6_4", "제한X", "4"),
        ("test6_5", "제한O+패턴", "3"),
        ("test6_6", "패턴+P2강화", "3"),
        ("test6_7", "패턴+P2제외(X)", "3"),
    ]
    for key, restrict, docs in configs:
        r = results.get(key, {})
        if "error" in r:
            print(f"  {key:<22} {restrict:<16} {docs:<4} ERROR: {r['error']}")
            continue
        p1_v = r.get("phase1", {}).get("vuln_count", 0)
        p1_r = r.get("phase1", {}).get("rejected_count", 0)
        p2_v = r.get("phase2", {}).get("vuln_count", 0)
        total = p1_v + p2_v
        tok = r.get("total_input_tokens", 0) + r.get("total_output_tokens", 0)
        time_s = r.get("total_response_time_sec", 0)
        print(f"  {key:<22} {restrict:<16} {docs:<4} {p1_v:<6} {p1_r:<6} {p2_v:<6} {total:<6} {tok:<12} {time_s:<8.1f}")

    # 비교 분석
    print(f"\n  📊 비교 분석:")
    t1 = results.get("test6_1", {})
    t2 = results.get("test6_2", {})
    t3 = results.get("test6_3", {})
    t4 = results.get("test6_4", {})
    t5 = results.get("test6_5", {})
    t6 = results.get("test6_6", {})
    t7 = results.get("test6_7", {})

    if "phase1" in t1 and "phase1" in t3:
        v1 = t1["phase1"]["vuln_count"]
        v3 = t3["phase1"]["vuln_count"]
        print(f"    [3문서] 제한O({v1}개) vs 제한X({v3}개) → {'제한 제거 시 더 많은 취약점 발견' if v3 > v1 else '비슷한 결과' if v3 == v1 else '제한이 더 효과적'}")

    if "phase1" in t2 and "phase1" in t4:
        v2 = t2["phase1"]["vuln_count"]
        v4 = t4["phase1"]["vuln_count"]
        print(f"    [4문서] 제한O({v2}개) vs 제한X({v4}개) → {'제한 제거 시 더 많은 취약점 발견' if v4 > v2 else '비슷한 결과' if v4 == v2 else '제한이 더 효과적'}")

    if "phase1" in t1 and "phase1" in t5:
        v1 = t1["phase1"]["vuln_count"]
        v5 = t5["phase1"]["vuln_count"]
        print(f"    [3문서] 제한O({v1}개) vs 제한O+패턴({v5}개) → {'패턴매칭이 더 많은 취약점 발견' if v5 > v1 else '비슷한 결과' if v5 == v1 else '패턴매칭이 더 적음'}")

    # ★★ 핵심: P2 중복 제거 효과 비교 (6_5 vs 6_6 vs 6_7)
    p2_counts = {}
    for key, t in [("6_5", t5), ("6_6", t6), ("6_7", t7)]:
        if "phase2" in t:
            p2_counts[key] = t["phase2"]["vuln_count"]
    if len(p2_counts) >= 2:
        print(f"    [P2 중복제거 비교]")
        for key, cnt in p2_counts.items():
            print(f"      {key}: P2 {cnt}개")
        if "6_5" in p2_counts and "6_6" in p2_counts:
            diff = p2_counts["6_5"] - p2_counts["6_6"]
            print(f"      6_5→6_6: {'제외강화로 {0}개 중복 제거'.format(diff) if diff > 0 else '비슷' if diff == 0 else '오히려 더 많음'}")
        if "6_5" in p2_counts and "6_7" in p2_counts:
            diff = p2_counts["6_5"] - p2_counts["6_7"]
            print(f"      6_5→6_7: {'상세정보만으로 {0}개 중복 제거'.format(diff) if diff > 0 else '비슷' if diff == 0 else '오히려 더 많음'}")
        if "6_6" in p2_counts and "6_7" in p2_counts:
            print(f"      6_6 vs 6_7: {'규칙이 더 효과적' if p2_counts['6_6'] < p2_counts['6_7'] else '비슷' if p2_counts['6_6'] == p2_counts['6_7'] else '규칙 없이도 충분'}")

    return results



# ──────────────────────────────────────────────────────────
# Test 7: 거부 사유 추적 + Confidence (Test4 강화판, 단일 호출)
#   num_docs=3 or 4 로 문서 수 조절
# ──────────────────────────────────────────────────────────
def _run_test7(num_docs):
    label = f"7_{num_docs}docs"
    print("\n" + "🟤" * 35)
    print(f"  Test {label}: Confidence + Source + 거부 사유 추적 (단일 호출)")
    print("🟤" * 35)

    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")
    doc3 = load_doc("iam_privesc_by_key_rotation")

    retrieved_context = f"""[문서 1 - vulnerable_lambda]
{doc1}

[문서 2 - eventbridge_target]
{doc2}

[문서 3 - iam_privesc_by_key_rotation]
{doc3}"""

    source_tags = """- "rag_doc_1": 문서 1(vulnerable_lambda)에서 파생
- "rag_doc_2": 문서 2(eventbridge_target)에서 파생
- "rag_doc_3": 문서 3(iam_privesc_by_key_rotation)에서 파생
- "zero_base": RAG 문서와 무관하게 자체 발견"""

    source_enum = "rag_doc_1|rag_doc_2|rag_doc_3|zero_base"
    context_docs = ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"]

    if num_docs >= 4:
        doc4 = load_doc("lambda_privesc")
        retrieved_context += f"""

[문서 4 - lambda_privesc]
{doc4}"""
        source_tags = source_tags.replace(
            '- "zero_base"',
            '- "rag_doc_4": 문서 4(lambda_privesc)에서 파생\n- "zero_base"'
        )
        source_enum = "rag_doc_1|rag_doc_2|rag_doc_3|rag_doc_4|zero_base"
        context_docs.append("lambda_privesc")

    prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 단순한 설정 오류 나열이 아니라, 현실적인 공격자가 실제로 악용 가능한 권한 조합과 신뢰 경계 붕괴 시나리오를 논리적으로 증명한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[분석 실행 전략 (반드시 준수)]
1. **Primary Task (RAG 시나리오 검증):**
   - 각 RAG 문서의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하라.
   - 재현 가능한 시나리오는 vulnerabilities에 포함하라.
   - 재현 불가능한 시나리오는 rejected_scenarios에 반드시 포함하고, 어떤 권한이 누락되어 재현 불가능한지 구체적으로 명시하라.

2. **Secondary Task (Zero-Base 확장 탐지):**
   - RAG 시나리오 검증 후, 클라우드 보안 지식을 총동원하여 인프라 전체를 스캔하라.
   - 컨텍스트에 없는 추가 취약점을 식별하여 보고하라 (source: "zero_base").

[심층 검증 및 오탐 제거 지침]
1. **[Effective Permission Calculation]**: Allow/Deny/SCP/Boundary 모두 대조하여 실제 유효 권한 계산.
2. **[Multi-hop Attack Simulation]**: sts:AssumeRole, Lambda 실행 역할 등 간접 경로 시뮬레이션.
3. **[간접 권한 주의]**: Lambda 실행 역할이 가진 권한은 Lambda를 트리거할 수 있는 사용자도 간접적으로 활용 가능.
4. **[False Positive Filtering]**: MFA, SourceIp 등 제어 조건을 검토.

[Confidence Score 산출 기준]
- 0.9~1.0: 확실히 재현 가능 (필요 권한이 모두 존재, 공격 경로 완전 증명)
- 0.7~0.9: 높은 확률 (대부분 조건 충족, 일부 환경 의존적)
- 0.5~0.7: 가능성 있음 (일부 권한 있으나 MFA/SourceIp 등 미확인)
- 0.3~0.5: 낮은 가능성 (핵심 권한 일부 누락)
- 0.0~0.3: 재현 불가 (필수 권한/리소스 없음)

[Source 태깅]
{source_tags}

출력 형식
아래 스키마의 순수 JSON 객체만 출력한다. 다른 텍스트, 마크다운, 코드펜스, 주석을 포함하지 않는다.
모든 문자열은 한국어로 작성하고, 전문 용어는 괄호 안에 영문을 병기할 수 있다.

스키마
{{{{
    "summary": {{{{ "high": 0, "medium": 0, "low": 0 }}}},
    "vulnerabilities": [
        {{{{
            "severity": "high|medium|low",
            "title": "문장형 제목",
            "description": "취약점 설명",
            "attackPath": ["단계1", "단계2"],
            "impact": "잠재적 영향",
            "recommendation": "권장 사항",
            "cvss_score": 0.0,
            "source": "{source_enum}",
            "confidence": 0.0,
            "confidence_reason": "점수 산출 근거"
        }}}}
    ],
    "rejected_scenarios": [
        {{{{
            "source": "{source_enum}",
            "doc_title": "문서 시나리오 제목",
            "rejection_reason": "거부 사유 (어떤 권한이 없어서 재현 불가능한지 구체적으로)",
            "missing_permissions": ["permission1", "permission2"]
        }}}}
    ]
}}}}
"""

    # 단일 호출이므로 출력 양이 많음 → max_tokens 8192 (모델 최대: 33,000)
    result = call_llm(prompt, max_tokens=8192)
    print_result(f"Test {label} (Confidence+거부추적)", result, context_docs)

    if result["parsed"]:
        vulns = result["parsed"].get("vulnerabilities", [])
        print(f"\n  📊 Confidence 분석:")
        for v in vulns:
            conf = v.get("confidence", "N/A")
            src = v.get("source", "N/A")
            reason = v.get("confidence_reason", "N/A")
            title = v.get("title", "N/A")
            print(f"    [{src}] confidence={conf} | {title}")
            print(f"           근거: {reason}")

        rejected = result["parsed"].get("rejected_scenarios", [])
        if rejected:
            print(f"\n  📊 거부된 RAG 시나리오: {len(rejected)}개")
            for r in rejected:
                src = r.get("source", "?")
                title = r.get("doc_title", "N/A")
                reason = r.get("rejection_reason", "N/A")
                missing = r.get("missing_permissions", [])
                print(f"    ❌ [{src}] {title}")
                print(f"       사유: {reason}")
                if missing:
                    print(f"       누락 권한: {', '.join(missing)}")
        else:
            print(f"\n  📊 거부된 시나리오: 없음 (모두 통과)")

        high_conf = [v for v in vulns if isinstance(v.get("confidence"), (int, float)) and v["confidence"] >= 0.7]
        low_conf = [v for v in vulns if isinstance(v.get("confidence"), (int, float)) and v["confidence"] < 0.7]
        print(f"\n  📊 필터링 결과 (confidence >= 0.7):")
        print(f"    통과: {len(high_conf)}개 / 제외: {len(low_conf)}개")

    return save_log(f"test7_{num_docs}docs", result, context_docs)


def run_test7_3docs():
    """Test 7 (3문서): 단일 호출 Confidence + 거부 추적"""
    return _run_test7(3)


def run_test7_4docs():
    """Test 7 (4문서): 단일 호출 Confidence + 거부 추적"""
    return _run_test7(4)


# ──────────────────────────────────────────────────────────
# 메인 실행
# ──────────────────────────────────────────────────────────
TESTS = {
    "baseline": run_baseline,
    "test1": run_test1,
    "test2": run_test2,
    "test3": run_test3,
    "test4": run_test4,
    "test5": run_test5,
    "test6_1": run_test6_1,
    "test6_2": run_test6_2,
    "test6_3": run_test6_3,
    "test6_4": run_test6_4,
    "test6_5": run_test6_5,
    "test6_6": run_test6_6,
    "test6_7": run_test6_7,
    "test6_all": run_test6_all,
}

def main():
    if len(sys.argv) < 2:
        print("사용법: python3 test_rag_context_accuracy.py [테스트명|all]")
        print("\n  === 기본 테스트 (baseline ~ test5) ===")
        print("  baseline  - 기존 프롬프트 + Top-1 (비교 기준)")
        print("  test1     - 기존 프롬프트 + Top-2")
        print("  test2     - 기존 프롬프트 + Top-3")
        print("  test3     - 2단계 분리 호출 (Primary + Secondary)")
        print("  test4     - Confidence Score + Source 태깅")
        print("  test5     - Chain-of-Verification (목록화 → 검증)")
        print("\n  === Test 6 변형 (제한 유무 × 문서 수) ===")
        print("  test6_1   - 제한O + 3문서 (Phase1 RAG검증 → Phase2 추가탐색)")
        print("  test6_2   - 제한O + 4문서")
        print("  test6_3   - 제한X + 3문서")
        print("  test6_4   - 제한X + 4문서")
        print("  test6_5   - ★ 제한O + 패턴매칭 + 3문서 (변형 경로 허용)")
        print("  test6_6   - ★★ 제한O + 패턴매칭 + P2제외강화 + 3문서")
        print("  test6_7   - ★★ 제한O + 패턴매칭 + P2제외(규칙X) + 3문서")
        print("  test6_all - ★ 위 7가지 모두 실행 후 비교 요약")
        print("\n  all       - 전체 순차 실행")
        sys.exit(1)

    target = sys.argv[1].lower()

    print(f"\n{'=' * 70}")
    print(f"  RAG Context 정확도 테스트")
    print(f"  실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  모델: {MODEL_ID}")
    print(f"  max_tokens (기본): {MAX_TOKENS}  |  모델 최대: 33,000")
    print(f"{'=' * 70}")

    if target == "all":
        results = {}
        for name, func in TESTS.items():
            if name == "test6_all":
                continue  # test6_all은 개별 test6_1~4를 포함하므로 중복 방지
            try:
                results[name] = func()
            except Exception as e:
                print(f"\n  ❌ {name} 실패: {e}")
                results[name] = {"error": str(e)}
        
        # 전체 비교 요약
        print(f"\n{'=' * 70}")
        print("📊 전체 비교 요약")
        print(f"{'=' * 70}")
        print(f"  {'테스트':<12} {'토큰(In)':<10} {'토큰(Out)':<10} {'시간(초)':<8} {'취약점수':<8} {'잘림'}")
        print(f"  {'─'*60}")
        for name, r in results.items():
            if "error" in r:
                print(f"  {name:<12} ERROR: {r['error']}")
                continue
            in_tok = r.get("total_input_tokens", r.get("input_tokens", "?"))
            out_tok = r.get("total_output_tokens", r.get("output_tokens", "?"))
            time_s = r.get("total_response_time_sec", r.get("response_time_sec", "?"))
            vuln_c = r.get("vuln_count", "?")
            if "phase1" in r:
                vuln_c = r.get("phase1", {}).get("vuln_count", 0) + r.get("phase2", {}).get("vuln_count", 0)
            trunc = r.get("truncated", "?")
            if "phase1" in r:
                trunc = r.get("phase1", {}).get("truncated", False) or r.get("phase2", {}).get("truncated", False)
            print(f"  {name:<12} {str(in_tok):<10} {str(out_tok):<10} {str(time_s):<8} {str(vuln_c):<8} {'⚠️' if trunc else '✅'}")
    
    elif target in TESTS:
        TESTS[target]()
    else:
        print(f"  ❌ 알 수 없는 테스트: {target}")
        print(f"  사용 가능: {', '.join(TESTS.keys())}, all")
        sys.exit(1)


if __name__ == "__main__":
    main()
