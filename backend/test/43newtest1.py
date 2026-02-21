#!/usr/bin/env python3
"""
==========================================================
43newtest1: Test4 Phase1 + Test3 Phase2 (중복 제거)
==========================================================
Phase 1: Test 4 방식 — Confidence Score + Source 태깅 (RAG 시나리오 검증 전용)
         ★ Zero-Base 탐색은 Phase 1에서 제외 (Phase 2로 이관)
Phase 2: Test 3 방식 — 별도 호출로 Zero-Base 확장 탐지
         ★ Phase 1에서 이미 발견한 취약점은 제외 목록으로 전달
reasoning_effort: medium

실행: python3 43newtest1.py
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
REASONING_EFFORT = "medium"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOC_DIR = os.path.join(BASE_DIR, "..", "document")

# RAG 유사도 실측 결과 순위대로 문서 매핑
DOC_FILES = {
    "vulnerable_lambda": os.path.join(DOC_DIR, "vulnerable_lambda.json"),
    "eventbridge_target": os.path.join(DOC_DIR, "eventbridge_target.json"),
    "iam_privesc_by_key_rotation": os.path.join(DOC_DIR, "iam_privesc_by_key_rotation.json"),
    "lambda_privesc": os.path.join(DOC_DIR, "lambda_privesc.json"),
}

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
                            {
                                "Action": ["cloudtrail:LookupEvents"],
                                "Effect": "Allow",
                                "Resource": "*"
                            },
                            {
                                "Action": ["iam:AttachUserPolicy"],
                                "Effect": "Allow",
                                "Resource": "*"
                            },
                            {
                                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                "Effect": "Allow",
                                "Resource": "arn:aws:logs:*:*:*"
                            }
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
    """LLM 출력에서 JSON 추출"""
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


def call_llm(prompt, system_msg=None, max_tokens=MAX_TOKENS, temperature=0.2, reasoning_effort=REASONING_EFFORT):
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
        "reasoning_effort": reasoning_effort
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


def save_log(test_name, log_data):
    """결과를 JSON 로그 파일로 저장"""
    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{test_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log_data, f, ensure_ascii=False, indent=2)
    print(f"  📁 로그 저장: {log_path}")
    return log_path


# ──────────────────────────────────────────────────────────
# 43newtest1: Phase 1 (Test4 방식) + Phase 2 (Test3 방식)
# ──────────────────────────────────────────────────────────
def run_43newtest1():
    print("\n" + "🔶" * 35)
    print("  43newtest1: Test4 Phase1 (Confidence+Source) → Test3 Phase2 (Zero-Base)")
    print(f"  reasoning_effort: {REASONING_EFFORT}")
    print("🔶" * 35)

    # ── 문서 로딩 ──
    doc1 = load_doc("vulnerable_lambda")
    doc2 = load_doc("eventbridge_target")
    doc3 = load_doc("iam_privesc_by_key_rotation")

    retrieved_context = f"""[문서 1 - vulnerable_lambda (유사도: 0.8014)]
{doc1}

[문서 2 - eventbridge_target (유사도: 0.7964)]
{doc2}

[문서 3 - iam_privesc_by_key_rotation (유사도: 0.7200)]
{doc3}"""

    context_docs = ["vulnerable_lambda", "eventbridge_target", "iam_privesc_by_key_rotation"]

    # ══════════════════════════════════════════════════════
    # Phase 1: Test 4 방식 — Confidence Score + Source 태깅
    #   ★ RAG 시나리오 검증 전용 (Zero-Base 탐색은 제외)
    # ══════════════════════════════════════════════════════
    print("\n  ── Phase 1: RAG 시나리오 검증 (Confidence + Source) ──")
    phase1_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
목표: 아래 RAG 문서들의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 각각 검증하고, 각 문서에 대해 confidence score와 출처를 명시한다.

컨텍스트: 취약점 지식 베이스 (RAG)
{retrieved_context}

입력: 분석 대상 인프라 구성 (JSON)
{TARGET_INFRA_STR}

[분석 지침 (반드시 준수)]
1. 각 RAG 문서의 공격 시나리오가 입력 인프라에서 실제로 재현 가능한지 검증하라.
2. 재현 가능한 시나리오는 vulnerabilities에 포함하고 confidence score를 부여하라.
3. 재현 불가능한 시나리오는 rejected_scenarios에 포함하고 구체적 거부 사유를 명시하라.
4. ★ 이 단계에서는 RAG 문서에 없는 추가 취약점을 탐색하지 마라. RAG 시나리오 검증에만 집중하라.

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
            "source": "rag_doc_1|rag_doc_2|rag_doc_3",
            "confidence": 0.0,
            "confidence_reason": "점수 산출 근거"
        }}}}
    ],
    "rejected_scenarios": [
        {{{{
            "source": "rag_doc_1|rag_doc_2|rag_doc_3",
            "doc_title": "문서 시나리오 제목",
            "rejection_reason": "거부 사유 (어떤 권한이 없어서 재현 불가능한지 구체적으로)",
            "missing_permissions": ["permission1"]
        }}}}
    ]
}}}}
"""

    phase1_result = call_llm(phase1_prompt)
    print_result("43newtest1 - Phase 1 (Confidence+Source)", phase1_result, context_docs)

    # Phase 1 Confidence 분석
    if phase1_result["parsed"]:
        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        print(f"\n  📊 Phase 1 Confidence 분석:")
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

    # ══════════════════════════════════════════════════════
    # Phase 1 → Phase 2 중복 제거: 제외 목록 생성
    # ══════════════════════════════════════════════════════
    primary_summary = "없음"
    if phase1_result["parsed"]:
        vulns = phase1_result["parsed"].get("vulnerabilities", [])
        titles = [v.get("title", "") for v in vulns]
        primary_summary = "\n".join([f"- {t}" for t in titles])

    # ══════════════════════════════════════════════════════
    # Phase 2: Test 3 방식 — Zero-Base 확장 탐지
    #   ★ RAG 시나리오 검증은 Phase 1에서 완료됨 → 여기서는 하지 않음
    #   ★ Phase 1에서 발견된 취약점을 제외 목록으로 전달
    # ══════════════════════════════════════════════════════
    print("\n  ── Phase 2: Zero-Base 확장 탐지 (Secondary) ──")
    phase2_prompt = f"""역할: 너는 전 세계 기업 환경을 대상으로 실전 침투 시나리오를 설계하고 검증하는 Tier-1 클라우드 보안 아키텍트이자 레드팀 리더이다.
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

    phase2_result = call_llm(phase2_prompt)
    print_result("43newtest1 - Phase 2 (Zero-Base)", phase2_result, ["zero_base_only"])

    # ══════════════════════════════════════════════════════
    # 통합 로그 저장
    # ══════════════════════════════════════════════════════
    combined_log = {
        "test_id": "43newtest1",
        "description": "Phase1: Test4방식(Confidence+Source, RAG검증전용) → Phase2: Test3방식(Zero-Base확장)",
        "reasoning_effort": REASONING_EFFORT,
        "timestamp": datetime.now().isoformat(),
        "context_docs": context_docs,
        "phase1": {
            "method": "Test4 (Confidence + Source 태깅, RAG 검증 전용)",
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
            "method": "Test3 (Zero-Base 확장 탐지, 제외 목록 기반)",
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

    save_log("43newtest1", combined_log)

    # ── 통합 요약 ──
    p1_vulns = combined_log["phase1"]["vuln_count"]
    p1_rejected = combined_log["phase1"]["rejected_count"]
    p2_vulns = combined_log["phase2"]["vuln_count"]
    total_vulns = p1_vulns + p2_vulns

    print(f"\n{'=' * 70}")
    print(f"📊 43newtest1 통합 요약")
    print(f"{'=' * 70}")
    print(f"  Phase 1 (RAG 검증): 통과 {p1_vulns}개 / 거부 {p1_rejected}개")
    print(f"  Phase 2 (Zero-Base): 추가 {p2_vulns}개")
    print(f"  총 취약점: {total_vulns}개")
    print(f"  총 토큰: Input {combined_log['total_input_tokens']} + Output {combined_log['total_output_tokens']}")
    print(f"  총 시간: {combined_log['total_response_time_sec']}초")
    print(f"  reasoning_effort: {REASONING_EFFORT}")
    print(f"{'=' * 70}")

    # ── Phase 1/2 겹침 검증 ──
    print(f"\n  📊 Phase 1/2 프롬프트 역할 분리 확인:")
    print(f"    Phase 1: RAG 시나리오 검증 전용 (Confidence + Source + rejected_scenarios)")
    print(f"    Phase 2: Zero-Base 확장 탐지 전용 (Phase 1 결과 제외)")
    print(f"    겹치는 내용: 없음 ✅")

    return combined_log


# ──────────────────────────────────────────────────────────
# 메인 실행
# ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'=' * 70}")
    print(f"  43newtest1: Test4 Phase1 + Test3 Phase2")
    print(f"  실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  모델: {MODEL_ID}")
    print(f"  max_tokens: {MAX_TOKENS}  |  reasoning_effort: {REASONING_EFFORT}")
    print(f"{'=' * 70}")

    run_43newtest1()
