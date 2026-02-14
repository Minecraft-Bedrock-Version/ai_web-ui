#!/usr/bin/env python3
"""
==========================================================
RAG 유사도 점수 격차 근본 해결 — 3가지 방향 비교 테스트
==========================================================

[목적]
JSON 직접 임베딩의 구조적 편향 문제를 해결하기 위한
3가지 방향의 효과를 동일 조건에서 비교

[테스트 방향]
  기준선: 현재 방식 (resources JSON만 임베딩)
  방향 1: 텍스트 기반 검색 (attack_narrative만 임베딩)
  방향 2: JSON 핵심 축약 + attack_narrative (비중 50:50)
  방향 3: JSON 전체 + attack_narrative 추가 (비중 유지)

[성공 기준]
  lambda_privesc ↔ iam_privesc 유사도가 낮을수록 좋음
  sqs_flag_shop과의 유사도 비율이 유지/개선되면 더 좋음
"""

import json
import os
import math
import boto3

# ── Bedrock 설정 ──
bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
MODEL_ID = "cohere.embed-multilingual-v3"

# ── pandyo.json 경로 ──
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON_PATH = os.path.join(BASE_DIR, "json", "pandyo", "pandyo.json")


# ══════════════════════════════════════════════════
# 공격 경로 설명 (Attack Narrative)
# ══════════════════════════════════════════════════
ATTACK_NARRATIVES = {
    "sqs_flag_shop": (
        "This scenario exploits an SQS message injection vulnerability. "
        "An IAM User assumes a role with SQS SendMessage permissions, "
        "sends a malicious message to the SQS queue, which triggers a Lambda function. "
        "The Lambda function processes the message and communicates with an EC2 instance "
        "that has access to an RDS database via its user data configuration. "
        "The attack chain: IAM User → AssumeRole → SQS SendMessage → Lambda Trigger → "
        "EC2 Access → RDS Database. The public EC2 instance connected to the IGW "
        "creates an external attack surface."
    ),
    "lambda_privesc": (
        "This scenario exploits Lambda-based privilege escalation. "
        "An IAM User with sts:AssumeRole permission assumes a role that has lambda:* "
        "and iam:PassRole permissions. The attacker creates or modifies a Lambda function, "
        "passing it a role with AdministratorAccess policy. When the Lambda function executes, "
        "it runs with full admin privileges, achieving complete privilege escalation. "
        "The attack chain: IAM User → AssumeRole → lambda:CreateFunction + iam:PassRole → "
        "Pass AdminRole to Lambda → Lambda executes with AdministratorAccess. "
        "The critical vulnerability is the combination of lambda:* and iam:PassRole on the same role."
    ),
    "iam_privesc_by_key_rotation": (
        "This scenario exploits IAM key rotation for privilege escalation to access Secrets Manager. "
        "An IAM User with iam:CreateAccessKey and iam:UpdateAccessKey permissions "
        "can create new access keys for OTHER IAM users, effectively impersonating them. "
        "The attacker creates an access key for a target user who has sts:AssumeRole, "
        "then assumes a role that has secretsmanager:GetSecretValue and "
        "secretsmanager:ListSecrets permissions. "
        "The attack chain: Attacker IAM User → CreateAccessKey(target user) → "
        "Impersonate target user → AssumeRole → Access Secrets Manager secrets. "
        "The critical vulnerability is iam:CreateAccessKey with Resource:* allowing "
        "key creation for any user, combined with a role granting Secrets Manager access."
    ),
}


# ══════════════════════════════════════════════════
# 핵심 구조 추출 함수 (방향 2용)
# ══════════════════════════════════════════════════
def extract_key_structure(resources, title):
    """JSON에서 핵심 요소만 추출하여 요약 텍스트 생성"""
    text_parts = []
    
    for res in resources:
        nodes = res.get("nodes", [])
        edges = res.get("edges", [])
        
        # 서비스 타입 추출
        services = set()
        for n in nodes:
            node_type = n.get("type") or n.get("node_type", "")
            if node_type:
                services.add(node_type)
        
        # 핵심 액션 추출
        key_actions = set()
        for n in nodes:
            props = n.get("properties", {})
            for policy_type in ["inline_policies", "attached_policies"]:
                policies = props.get(policy_type, [])
                if isinstance(policies, list):
                    for p in policies:
                        stmts = p.get("Statement", [p]) if isinstance(p, dict) else []
                        for stmt in stmts:
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            for a in actions:
                                # 공통 읽기 패턴 제외
                                if not any(pat in a for pat in ["Get*", "List*", "logs:", "Describe"]):
                                    key_actions.add(a)
        
        # 관계(Edge) 타입 추출
        relations = set()
        for e in edges:
            rel = e.get("relation", "")
            if rel:
                relations.add(rel)
        
        text_parts.append(f"Services: {', '.join(sorted(services))}")
        text_parts.append(f"Key Actions: {', '.join(sorted(key_actions))}")
        text_parts.append(f"Relations: {', '.join(sorted(relations))}")
    
    return "\n".join(text_parts)


# ══════════════════════════════════════════════════
# 임베딩 및 유사도 함수
# ══════════════════════════════════════════════════
def get_embedding(text, input_type="search_document"):
    """Cohere embed-v4로 텍스트를 벡터로 변환"""
    request_body = {
        "texts": [text],
        "input_type": input_type,
        "truncate": "NONE"
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(request_body))
    body = json.loads(response["body"].read())
    emb = body.get("embeddings")
    return emb.get("float")[0] if isinstance(emb, dict) else emb[0]


def cosine_sim(a, b):
    """두 벡터의 코사인 유사도 (순수 Python)"""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    return dot / (norm_a * norm_b) if norm_a and norm_b else 0.0


# ══════════════════════════════════════════════════
# 메인 비교 테스트
# ══════════════════════════════════════════════════
def main():
    # 데이터 로드
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    docs = {}
    for item in data:
        title = item["title"]
        docs[title] = item
    
    titles = ["sqs_flag_shop", "lambda_privesc", "iam_privesc_by_key_rotation"]
    
    print("=" * 70)
    print("RAG 유사도 점수 격차 근본 해결 — 3가지 방향 비교")
    print("=" * 70)
    
    # ── 임베딩 입력 준비 ──
    inputs = {}
    
    for title in titles:
        resources = docs[title]["resources"]
        raw_json = json.dumps(resources, indent=2, ensure_ascii=False)
        narrative = ATTACK_NARRATIVES[title]
        key_struct = extract_key_structure(resources, title)
        
        # 기준선: JSON만
        inputs.setdefault("baseline", {})[title] = raw_json
        
        # 방향 1: narrative만 (JSON 완전 제거)
        inputs.setdefault("dir1_narrative_only", {})[title] = narrative
        
        # 방향 2: 핵심 축약 + narrative (50:50 비중)
        inputs.setdefault("dir2_key_struct", {})[title] = f"{key_struct}\n\n{narrative}"
        
        # 방향 3: JSON 전체 + narrative 추가
        inputs.setdefault("dir3_json_plus_narrative", {})[title] = f"{raw_json}\n\n[ATTACK_NARRATIVE]\n{narrative}"
    
    # ── 각 방향별 임베딩 및 유사도 계산 ──
    methods = [
        ("baseline",              "기준선 (JSON만)"),
        ("dir1_narrative_only",   "방향1: narrative만"),
        ("dir2_key_struct",       "방향2: 핵심축약+narrative"),
        ("dir3_json_plus_narrative", "방향3: JSON+narrative"),
    ]
    
    results = {}
    
    for method_key, method_name in methods:
        print(f"\n{'─' * 70}")
        print(f"▶ {method_name}")
        print(f"{'─' * 70}")
        
        # 입력 텍스트 길이 출력
        for title in titles:
            text = inputs[method_key][title]
            print(f"  [{title}] 입력 길이: {len(text)}자")
        
        # 임베딩 생성
        embeddings = {}
        for title in titles:
            text = inputs[method_key][title]
            print(f"  [{title}] 임베딩 중...")
            embeddings[title] = get_embedding(text)
        
        # 유사도 계산
        pairs = [
            ("lambda_privesc", "iam_privesc_by_key_rotation", "★ 핵심"),
            ("sqs_flag_shop",  "lambda_privesc",              "참고"),
            ("sqs_flag_shop",  "iam_privesc_by_key_rotation", "참고"),
        ]
        
        method_results = {}
        for t1, t2, label in pairs:
            sim = cosine_sim(embeddings[t1], embeddings[t2])
            pair_key = f"{t1} ↔ {t2}"
            method_results[pair_key] = sim
        
        results[method_key] = method_results
        
        # 결과 출력
        print(f"\n  유사도 결과:")
        for (t1, t2, label), (pair_key, sim) in zip(pairs, method_results.items()):
            baseline_sim = results.get("baseline", {}).get(pair_key, sim)
            delta = sim - baseline_sim
            delta_str = f"  ({delta:+.4f})" if method_key != "baseline" else ""
            print(f"    [{label}] {t1:30s} ↔ {t2:30s}: {sim:.4f}{delta_str}")
    
    # ══════════════════════════════════════════════════
    # 종합 비교 표
    # ══════════════════════════════════════════════════
    print(f"\n{'=' * 70}")
    print("종합 비교 결과")
    print(f"{'=' * 70}")
    
    core_pair = "lambda_privesc ↔ iam_privesc_by_key_rotation"
    baseline_core = results["baseline"][core_pair]
    
    print(f"\n{'방법':<30s} | {'lambda↔iam':>10s} | {'개선폭':>8s} | {'개선율':>7s}")
    print("-" * 65)
    
    for method_key, method_name in methods:
        sim = results[method_key][core_pair]
        delta = sim - baseline_core
        pct = (delta / baseline_core) * 100
        delta_str = f"{delta:+.4f}" if method_key != "baseline" else "---"
        pct_str = f"{pct:+.1f}%" if method_key != "baseline" else "---"
        print(f"{method_name:<30s} | {sim:>10.4f} | {delta_str:>8s} | {pct_str:>7s}")
    
    # ── 확장성 분석 ──
    print(f"\n{'=' * 70}")
    print("확장성 분석: 각 방향별 서비스 도메인 분리 효과")
    print(f"{'=' * 70}")
    
    for method_key, method_name in methods:
        mr = results[method_key]
        sqs_lam = mr["sqs_flag_shop ↔ lambda_privesc"]
        sqs_iam = mr["sqs_flag_shop ↔ iam_privesc_by_key_rotation"]
        lam_iam = mr[core_pair]
        
        # 이상적: core pair 유사도가 다른 pair보다 낮아야 함
        cross_domain_avg = (sqs_lam + sqs_iam) / 2
        same_domain_gap = lam_iam - cross_domain_avg
        
        print(f"\n  {method_name}:")
        print(f"    IAM 내부 유사도 (lambda↔iam):     {lam_iam:.4f}")
        print(f"    서비스 간 평균 (sqs↔IAM들):       {cross_domain_avg:.4f}")
        print(f"    도메인 내/간 차이:                 {same_domain_gap:+.4f}", end="")
        
        if same_domain_gap < 0.05:
            print(" ✅ 충분히 분리됨")
        elif same_domain_gap < 0.15:
            print(" ⚠️  개선 필요")
        else:
            print(" ❌ 분리 불충분 (같은 도메인 내 구분 실패)")
    
    print(f"\n{'=' * 70}")
    print("결론 및 추천")
    print(f"{'=' * 70}")
    
    # 최적 방향 찾기
    best_key = min(
        [k for k, _ in methods if k != "baseline"],
        key=lambda k: results[k][core_pair]
    )
    best_name = dict(methods)[best_key]
    best_sim = results[best_key][core_pair]
    best_delta = best_sim - baseline_core
    
    print(f"\n  최적 방향: {best_name}")
    print(f"  핵심 유사도: {baseline_core:.4f} → {best_sim:.4f} (개선: {best_delta:+.4f})")
    print(f"\n  ※ 이 결과를 바탕으로 최적 방향을 실제 시스템에 적용합니다.")


if __name__ == "__main__":
    main()
