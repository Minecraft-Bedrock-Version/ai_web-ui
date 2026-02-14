# =========================================================
# 테스트 3: 점진적 삭제 (Ablation) 테스트 (Bedrock API 필요)
# 목적: iam_privesc 문서에서 구성 요소를 하나씩 제거하며
#       lambda_privesc와의 유사도 변화를 관찰하여 근본 원인 확인
# 실행: python test_ablation.py (EC2에서 실행)
# =========================================================
import boto3
import json
import os
import copy
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


def embed_resources(resources):
    """resources를 mbv_embed.py와 동일한 방식으로 임베딩"""
    resources_str = json.dumps(resources, indent=2, ensure_ascii=False)
    return get_embedding(resources_str)


def main():
    if not os.path.exists(PANDYO_PATH):
        print(f"❌ 파일을 찾을 수 없습니다: {PANDYO_PATH}")
        return

    with open(PANDYO_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 각 문서를 title로 분류
    doc_map = {item['title']: item for item in data}
    
    print("=" * 70)
    print("📊 [테스트 3] Ablation 테스트 (점진적 삭제)")
    print("=" * 70)

    # =============================================
    # 1. 기준선: 원본 벡터 생성
    # =============================================
    print("\n🔧 기준선 벡터 생성 중...")
    originals = {}
    for title, item in doc_map.items():
        print(f"  임베딩 중: {title}...")
        originals[title] = embed_resources(item['resources'])
        print(f"  ✅ {title} 완료")

    # 기준선 유사도
    print("\n" + "─" * 60)
    print("📌 기준선 (원본 유사도)")
    print("─" * 60)
    baseline_lambda_iam = cosine_sim(originals['iam_privesc_by_key_rotation'], originals['lambda_privesc'])
    baseline_sqs_iam = cosine_sim(originals['iam_privesc_by_key_rotation'], originals['sqs_flag_shop'])
    baseline_lambda_sqs = cosine_sim(originals['lambda_privesc'], originals['sqs_flag_shop'])
    
    print(f"  iam_privesc ↔ lambda_privesc : {baseline_lambda_iam:.4f}")
    print(f"  iam_privesc ↔ sqs_flag_shop  : {baseline_sqs_iam:.4f}")
    print(f"  lambda_privesc ↔ sqs_flag_shop: {baseline_lambda_sqs:.4f}")

    # =============================================
    # 2. Ablation 테스트 실행
    # =============================================
    iam_original = copy.deepcopy(doc_map['iam_privesc_by_key_rotation'])

    results = []

    def run_ablation(label, modify_fn):
        """데이터 수정 → 재임베딩 → 모든 문서와 유사도 비교"""
        modified = copy.deepcopy(iam_original)
        modify_fn(modified)
        modified_vec = embed_resources(modified['resources'])
        
        sim_lambda = cosine_sim(modified_vec, originals['lambda_privesc'])
        sim_sqs = cosine_sim(modified_vec, originals['sqs_flag_shop'])
        sim_iam_orig = cosine_sim(modified_vec, originals['iam_privesc_by_key_rotation'])
        
        delta_lambda = sim_lambda - baseline_lambda_iam
        delta_sqs = sim_sqs - baseline_sqs_iam
        
        results.append({
            'label': label,
            'vs_lambda': sim_lambda,
            'vs_sqs': sim_sqs,
            'vs_self': sim_iam_orig,
            'delta_lambda': delta_lambda,
            'delta_sqs': delta_sqs,
        })
        
        print(f"\n🔬 [{label}]")
        print(f"   vs lambda_privesc   : {sim_lambda:.4f} (변화: {delta_lambda:+.4f})")
        print(f"   vs sqs_flag_shop    : {sim_sqs:.4f} (변화: {delta_sqs:+.4f})")
        print(f"   vs iam_privesc(원본): {sim_iam_orig:.4f}")

    print("\n" + "=" * 70)
    print("🔬 Ablation 실험 시작 (iam_privesc 문서 기준)")
    print("=" * 70)

    # Ablation 1: secretsmanager 노드 제거
    def remove_secretsmanager_node(data):
        resources = data['resources'][0]
        resources['nodes'] = [
            n for n in resources['nodes'] 
            if n.get('node_type') != 'secretsmanager' and n.get('type') != 'secretsmanager'
        ]
        resources['edges'] = [
            e for e in resources['edges'] 
            if 'secretsmanager' not in str(e).lower()
        ]
    
    print("\n  ⏳ Ablation 1: secretsmanager 노드/edge 제거...")
    run_ablation("secretsmanager 노드 + edge 제거", remove_secretsmanager_node)

    # Ablation 2: secretsmanager 전부 제거 (노드 + Action)
    def remove_secretsmanager_all(data):
        remove_secretsmanager_node(data)
        text = json.dumps(data['resources'])
        text = text.replace('secretsmanager:ListSecrets', 'REMOVED_ACTION')
        text = text.replace('secretsmanager:GetSecretValue', 'REMOVED_ACTION')
        text = text.replace('secretsmanager', 'REMOVED_SERVICE')
        data['resources'] = json.loads(text)
    
    print("\n  ⏳ Ablation 2: secretsmanager 전부 제거...")
    run_ablation("secretsmanager 완전 제거 (노드+Action+텍스트)", remove_secretsmanager_all)

    # Ablation 3: 공통 IAM 읽기 패턴 제거
    def remove_common_iam_readonly(data):
        text = json.dumps(data['resources'])
        for pattern in ['iam:Get*', 'iam:List*', 'iam:GenerateCredentialReport',
                        'iam:GenerateServiceLastAccessedDetails',
                        'iam:SimulateCustomPolicy', 'iam:SimulatePrincipalPolicy']:
            text = text.replace(pattern, 'REMOVED_COMMON_READONLY')
        data['resources'] = json.loads(text)
    
    print("\n  ⏳ Ablation 3: 공통 IAM 읽기 권한 제거...")
    run_ablation("공통 IAM 읽기 권한 제거 (Get*/List*/Simulate*)", remove_common_iam_readonly)

    # Ablation 4: 공통 edge 관계 제거
    def remove_common_edges(data):
        resources = data['resources'][0]
        common_relations = {'IAM_USER_ACCESS_IAM'}
        resources['edges'] = [
            e for e in resources['edges']
            if e.get('relation') not in common_relations
        ]
    
    print("\n  ⏳ Ablation 4: 공통 IAM_USER_ACCESS_IAM edge 제거...")
    run_ablation("IAM_USER_ACCESS_IAM edge 제거", remove_common_edges)

    # Ablation 5: iam:CreateAccessKey 관련 제거
    def remove_create_access_key(data):
        text = json.dumps(data['resources'])
        text = text.replace('iam:CreateAccessKey', 'REMOVED_ACTION')
        text = text.replace('iam:DeleteAccessKey', 'REMOVED_ACTION')
        data['resources'] = json.loads(text)
    
    print("\n  ⏳ Ablation 5: iam:CreateAccessKey/DeleteAccessKey 제거...")
    run_ablation("iam:CreateAccessKey + DeleteAccessKey 제거", remove_create_access_key)

    # Ablation 6: 모든 공통 패턴 동시 제거 (최대 효과 테스트)
    def remove_all_common(data):
        remove_secretsmanager_all(data)
        remove_common_iam_readonly(data)
        remove_common_edges(data)
    
    print("\n  ⏳ Ablation 6: 모든 공통/고유 패턴 동시 제거 (최대 효과)...")
    run_ablation("secretsmanager + 공통 읽기 + 공통 edge 모두 제거", remove_all_common)

    # =============================================
    # 3. 결과 요약
    # =============================================
    print("\n" + "=" * 70)
    print("📝 Ablation 결과 요약")
    print("=" * 70)

    print(f"\n{'실험':>45} | {'vs lambda':>10} | {'변화':>8} | {'해석':>8}")
    print("─" * 80)
    print(f"{'기준선 (원본)':>45} | {baseline_lambda_iam:>10.4f} | {'─':>8} | {'─':>8}")
    
    for r in results:
        direction = "↑ 위험" if r['delta_lambda'] > 0.005 else ("↓ 개선" if r['delta_lambda'] < -0.005 else "→ 변화없음")
        print(f"{r['label']:>45} | {r['vs_lambda']:>10.4f} | {r['delta_lambda']:>+8.4f} | {direction:>8}")

    # =============================================
    # 4. 근본 원인 판정
    # =============================================
    print("\n" + "=" * 70)
    print("🎯 근본 원인 판정")
    print("=" * 70)

    # 가장 큰 변화를 일으킨 실험 찾기
    max_decrease = min(results, key=lambda r: r['delta_lambda'])
    max_increase = max(results, key=lambda r: r['delta_lambda'])

    if max_increase['delta_lambda'] > 0.01:
        print(f"\n  📌 고유 요소 제거 시 유사도 증가:")
        print(f"     [{max_increase['label']}] → lambda와 유사도 {max_increase['delta_lambda']:+.4f}")
        print(f"     → 이 요소가 문서를 구분하는 핵심 역할을 함")
        print(f"     → 해결책: 방안 1 (가중 강조)에서 이 요소를 강조하면 효과적")

    if max_decrease['delta_lambda'] < -0.01:
        print(f"\n  📌 공통 패턴 제거 시 유사도 감소:")
        print(f"     [{max_decrease['label']}] → lambda와 유사도 {max_decrease['delta_lambda']:+.4f}")
        print(f"     → 이 패턴이 벡터를 지배하여 유사도를 높이는 원인")
        print(f"     → 해결책: 방안 3 (구조화 임베딩) 또는 방안 1에서 이 패턴 제외")

    # 종합 판정
    all_deltas = [abs(r['delta_lambda']) for r in results]
    if max(all_deltas) < 0.02:
        print(f"\n  ⚠️ 모든 Ablation에서 유사도 변화가 미미합니다 (최대: {max(all_deltas):.4f})")
        print(f"     → 임베딩 모델이 IAM 문서를 구조적으로 구분하지 못하는 것이 근본 원인")
        print(f"     → 해결책: 방안 2 (Rule-based 보정)이 가장 효과적")


if __name__ == "__main__":
    main()
