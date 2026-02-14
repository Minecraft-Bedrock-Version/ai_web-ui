# =========================================================
# 테스트 2: 임베딩 코사인 유사도 매트릭스 (Bedrock API 필요)
# 목적: pandyo.json 문서들의 실제 벡터 간 코사인 유사도 측정
# 실행: python test_cosine_matrix.py (EC2에서 실행)
# =========================================================
import boto3
import json
import os
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


def main():
    if not os.path.exists(PANDYO_PATH):
        print(f"❌ 파일을 찾을 수 없습니다: {PANDYO_PATH}")
        return

    with open(PANDYO_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # =============================================
    # 1. 각 문서의 resources를 임베딩
    # =============================================
    print("=" * 70)
    print("📊 [테스트 2] 임베딩 코사인 유사도 매트릭스")
    print("=" * 70)

    vectors = {}
    for item in data:
        title = item['title']
        # mbv_embed.py와 동일한 방식: resources를 JSON 문자열로
        resources_str = json.dumps(item['resources'], indent=2, ensure_ascii=False)
        print(f"  임베딩 중: {title} (텍스트 길이: {len(resources_str)}자)")
        vectors[title] = get_embedding(resources_str)
        print(f"  ✅ {title} 완료 (벡터 차원: {len(vectors[title])})")

    # =============================================
    # 2. 코사인 유사도 매트릭스
    # =============================================
    titles = list(vectors.keys())

    print("\n" + "=" * 70)
    print("📐 문서 간 코사인 유사도 매트릭스 (search_document 모드)")
    print("=" * 70)

    # 헤더
    header = f"{'':>35}"
    for t in titles:
        header += f" {t[:15]:>15}"
    print(header)

    # 매트릭스 출력
    for t1 in titles:
        row = f"{t1:>35}"
        for t2 in titles:
            sim = cosine_sim(vectors[t1], vectors[t2])
            row += f" {sim:>15.4f}"
        print(row)

    # =============================================
    # 3. 쌍별 상세 분석
    # =============================================
    print("\n" + "=" * 70)
    print("🔍 쌍별 상세 분석")
    print("=" * 70)

    pairs = []
    for i in range(len(titles)):
        for j in range(i + 1, len(titles)):
            sim = cosine_sim(vectors[titles[i]], vectors[titles[j]])
            pairs.append((titles[i], titles[j], sim))

    pairs.sort(key=lambda x: x[2], reverse=True)
    for t1, t2, sim in pairs:
        risk = "🔴 위험" if sim > 0.75 else ("⚠️ 주의" if sim > 0.6 else "✅ 안전")
        print(f"  {risk} {t1} ↔ {t2}: {sim:.4f}")

    # =============================================
    # 4. 벡터 통계
    # =============================================
    print("\n" + "=" * 70)
    print("📈 벡터 통계")
    print("=" * 70)
    for title, vec in vectors.items():
        v = np.array(vec)
        print(f"\n📄 {title}")
        print(f"   L2 노름: {np.linalg.norm(v):.4f}")
        print(f"   평균: {np.mean(v):.6f}")
        print(f"   표준편차: {np.std(v):.6f}")
        print(f"   최대값: {np.max(v):.6f}")
        print(f"   최소값: {np.min(v):.6f}")

    # =============================================
    # 5. 결론
    # =============================================
    print("\n" + "=" * 70)
    print("📝 분석 결론")
    print("=" * 70)

    max_pair = pairs[0]
    min_pair = pairs[-1]
    print(f"  가장 유사한 쌍: {max_pair[0]} ↔ {max_pair[1]} ({max_pair[2]:.4f})")
    print(f"  가장 다른 쌍:  {min_pair[0]} ↔ {min_pair[1]} ({min_pair[2]:.4f})")
    print(f"  최대-최소 격차: {max_pair[2] - min_pair[2]:.4f}")

    if max_pair[2] > 0.75:
        print(f"\n  ⚠️ 가장 유사한 쌍의 유사도가 {max_pair[2]:.4f}로 높습니다.")
        print(f"     → 문서 30개 이상에서 오매칭 위험이 존재합니다.")
        print(f"     → 임베딩 개선 (가중 강조, 구조화) 또는 후처리 보정이 필요합니다.")


if __name__ == "__main__":
    main()
