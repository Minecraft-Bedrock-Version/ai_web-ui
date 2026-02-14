# =========================================================
# 테스트 4: 서비스 시그니처 분리 테스트 (Bedrock API 필요)
# 목적: 공통 IAM 패턴을 제거한 "시그니처"만 임베딩했을 때
#       문서 간 분리도가 개선되는지 확인 (해결책 방향 사전 검증)
# 실행: python test_service_signature.py (EC2에서 실행)
# =========================================================
import boto3
import json
import os
import re
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PANDYO_PATH = os.path.join(BASE_DIR, "..", "json", "pandyo", "pandyo.json")

REGION = "ap-northeast-1"
MODEL_ID = "cohere.embed-v4:0"
bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)


def get_embedding(text, input_type="search_document"):
    """Bedrock Cohere embed-v4로 텍스트를 벡터로 변환"""
    native_request = {
        "texts": [text],
        "input_type": input_type,
        "truncate": "NONE"
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request))
    res_body = json.loads(response.get('body').read())
    embeddings = res_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]


def cosine_sim(a, b):
    """두 벡터의 코사인 유사도 계산"""
    a, b = np.array(a), np.array(b)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def extract_service_signature(resources):
    """공통 IAM 패턴을 제거하고 서비스 고유 시그니처만 추출"""
    text = json.dumps(resources, ensure_ascii=False)

    # 공통 패턴 제거 목록
    common_patterns = [
        # 노드 타입 공통
        '"type": "iam_user"', '"type": "iam_role"',
        # Action 공통
        'iam:Get*', 'iam:List*', 'sts:AssumeRole',
        'iam:GenerateCredentialReport', 'iam:GenerateServiceLastAccessedDetails',
        'iam:SimulateCustomPolicy', 'iam:SimulatePrincipalPolicy',
        # Edge 관계 공통
        'IAM_USER_ACCESS_IAM', 'IAM_USER_CAN_ASSUME_ROLE',
        'IAM_USER_ASSUME_ROLE', 'ASSUME_ROLE', 'IAM_ROLE_ACCESS_IAM',
        # 구조적 공통
        'assume_role_policy', 'attached_policies', 'inline_policies',
        'group_policies',
        # 값 공통
        '"Effect": "Allow"', '"Resource": "*"',
        'This User has access to IAM.',
        'This is a role that an IAM User can assume.',
        'This User can Assume Roles.',
    ]

    for pattern in common_patterns:
        text = text.replace(pattern, '')

    return text


def extract_weighted_signature(resources):
    """방안 1 (가중 강조) 시뮬레이션: 원본 + 고유 요소 강조"""
    original_text = json.dumps(resources, ensure_ascii=False)
    
    # 고유 요소 추출
    emphasis_parts = []
    
    if isinstance(resources, list):
        resources_list = resources
    else:
        resources_list = [resources]

    for res in resources_list:
        for node in res.get("nodes", []):
            node_type = node.get("type", node.get("node_type", ""))
            # 비공통 서비스
            if node_type not in ("iam_user", "iam_role", ""):
                emphasis_parts.append(f"KEY_SERVICE: {node_type}")

            # 정책에서 고유 Action 추출
            props = node.get("properties", {})
            for policy_key in ("inline_policies", "attached_policies"):
                policies = props.get(policy_key, [])
                for policy in policies:
                    # Statement에서 Action 추출
                    statements = policy.get("Statement", [policy] if "Action" in policy else [])
                    for stmt in statements:
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        for action in actions:
                            # 공통 읽기 권한 제외
                            if action not in ("sts:AssumeRole", "iam:Get*", "iam:List*",
                                              "iam:GenerateCredentialReport",
                                              "iam:SimulateCustomPolicy",
                                              "iam:SimulatePrincipalPolicy",
                                              "iam:GenerateServiceLastAccessedDetails"):
                                emphasis_parts.append(f"KEY_ACTION: {action}")

        for edge in res.get("edges", []):
            relation = edge.get("relation", "")
            if relation not in ("IAM_USER_ACCESS_IAM", "ASSUME_ROLE",
                                "IAM_USER_ASSUME_ROLE", "IAM_USER_CAN_ASSUME_ROLE",
                                "IAM_ROLE_ACCESS_IAM"):
                emphasis_parts.append(f"KEY_RELATION: {relation}")

    emphasis_text = "\n".join(emphasis_parts)
    # 원본 + 3번 반복 강조
    return f"{original_text}\n\n{emphasis_text}\n{emphasis_text}\n{emphasis_text}"


def main():
    if not os.path.exists(PANDYO_PATH):
        print(f"❌ 파일을 찾을 수 없습니다: {PANDYO_PATH}")
        return

    with open(PANDYO_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("=" * 70)
    print("📊 [테스트 4] 서비스 시그니처 분리 테스트")
    print("=" * 70)

    # =============================================
    # 방법 A: 전체 임베딩 (기준선)
    # =============================================
    print("\n🔧 방법 A: 전체 임베딩 (기준선)")
    full_vectors = {}
    for item in data:
        title = item['title']
        full_str = json.dumps(item['resources'], indent=2, ensure_ascii=False)
        print(f"  임베딩 중: {title}...")
        full_vectors[title] = get_embedding(full_str)

    # =============================================
    # 방법 B: 시그니처만 임베딩 (공통 제거)
    # =============================================
    print("\n🔧 방법 B: 시그니처 임베딩 (공통 패턴 제거)")
    sig_vectors = {}
    for item in data:
        title = item['title']
        sig_str = extract_service_signature(item['resources'])
        print(f"  임베딩 중: {title} (시그니처 길이: {len(sig_str)}자)...")
        sig_vectors[title] = get_embedding(sig_str)

    # =============================================
    # 방법 C: 가중 강조 임베딩 (방안 1 시뮬레이션)
    # =============================================
    print("\n🔧 방법 C: 가중 강조 임베딩 (방안 1 시뮬레이션)")
    weighted_vectors = {}
    for item in data:
        title = item['title']
        weighted_str = extract_weighted_signature(item['resources'])
        print(f"  임베딩 중: {title} (가중 텍스트 길이: {len(weighted_str)}자)...")
        weighted_vectors[title] = get_embedding(weighted_str)

    # =============================================
    # 결과 비교
    # =============================================
    titles = list(full_vectors.keys())

    print("\n" + "=" * 70)
    print("📐 코사인 유사도 비교")
    print("=" * 70)

    methods = {
        "A. 전체 (기준선)": full_vectors,
        "B. 시그니처 (공통 제거)": sig_vectors,
        "C. 가중 강조 (방안 1)": weighted_vectors,
    }

    # 각 방법별 쌍 유사도
    summary = {}
    for method_name, vectors in methods.items():
        print(f"\n[{method_name}]")
        pairs = []
        for i in range(len(titles)):
            for j in range(i + 1, len(titles)):
                sim = cosine_sim(vectors[titles[i]], vectors[titles[j]])
                pairs.append((titles[i], titles[j], sim))
                print(f"  {titles[i]} ↔ {titles[j]}: {sim:.4f}")
        summary[method_name] = pairs

    # =============================================
    # 격차 개선 분석
    # =============================================
    print("\n" + "=" * 70)
    print("📊 격차 개선 분석 (lambda_privesc ↔ iam_privesc 중심)")
    print("=" * 70)

    print(f"\n{'방법':>30} | {'lambda↔iam':>12} | {'lambda↔sqs':>12} | {'iam↔sqs':>12} | {'격차 개선':>10}")
    print("─" * 85)

    baseline_gap = None
    for method_name, pairs in summary.items():
        pair_map = {}
        for t1, t2, sim in pairs:
            key = tuple(sorted([t1, t2]))
            pair_map[key] = sim

        lambda_iam = pair_map.get(tuple(sorted(['lambda_privesc', 'iam_privesc_by_key_rotation'])), 0)
        lambda_sqs = pair_map.get(tuple(sorted(['lambda_privesc', 'sqs_flag_shop'])), 0)
        iam_sqs = pair_map.get(tuple(sorted(['iam_privesc_by_key_rotation', 'sqs_flag_shop'])), 0)

        if baseline_gap is None:
            baseline_gap = lambda_iam
            improvement = "─ (기준)"
        else:
            delta = baseline_gap - lambda_iam
            improvement = f"{delta:+.4f}"

        print(f"{method_name:>30} | {lambda_iam:>12.4f} | {lambda_sqs:>12.4f} | {iam_sqs:>12.4f} | {improvement:>10}")

    # =============================================
    # 추출된 시그니처 미리보기
    # =============================================
    print("\n" + "=" * 70)
    print("🔍 각 문서의 가중 강조 시그니처 미리보기")
    print("=" * 70)
    for item in data:
        title = item['title']
        weighted_str = extract_weighted_signature(item['resources'])
        # 강조 부분만 추출 (마지막 부분)
        parts = weighted_str.split("\n\n", 1)
        if len(parts) > 1:
            emphasis = parts[1].split("\n")
            unique_emphasis = list(dict.fromkeys(emphasis))  # 중복 제거 (보기용)
            print(f"\n📄 {title}:")
            for e in unique_emphasis[:15]:  # 최대 15개만 표시
                if e.strip():
                    print(f"   {e}")
            if len(unique_emphasis) > 15:
                print(f"   ... 외 {len(unique_emphasis) - 15}개")

    # =============================================
    # 최종 결론
    # =============================================
    print("\n" + "=" * 70)
    print("📝 최종 결론 및 해결책 추천")
    print("=" * 70)

    # 각 방법의 lambda↔iam 유사도
    method_scores = {}
    for method_name, pairs in summary.items():
        for t1, t2, sim in pairs:
            if set([t1, t2]) == set(['lambda_privesc', 'iam_privesc_by_key_rotation']):
                method_scores[method_name] = sim

    best_method = min(method_scores, key=method_scores.get)
    best_score = method_scores[best_method]

    print(f"\n  기준선 (전체 임베딩) lambda↔iam: {method_scores.get('A. 전체 (기준선)', 'N/A')}")
    print(f"  최적 방법: {best_method}")
    print(f"  최적 방법 lambda↔iam: {best_score:.4f}")
    print(f"  개선폭: {method_scores.get('A. 전체 (기준선)', 0) - best_score:.4f}")

    if best_method == "C. 가중 강조 (방안 1)":
        print(f"\n  ✅ 방안 1 (가중 강조 임베딩)이 가장 효과적입니다!")
        print(f"     → 원본 JSON 보존 + 고유 요소 강조로 분리도 개선")
    elif best_method == "B. 시그니처 (공통 제거)":
        print(f"\n  ⚠️ 시그니처 임베딩이 더 효과적이지만 맥락 손실 위험이 있습니다.")
        print(f"     → 방안 3 (구조화 임베딩) 고려, but 방안 1이 더 안전한 선택")
    else:
        print(f"\n  ⚠️ 임베딩 개선만으로는 부족합니다.")
        print(f"     → 방안 2 (Rule-based 보정) 필수")


if __name__ == "__main__":
    main()
