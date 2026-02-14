# =========================================================
# 테스트 1: 키워드 오버랩 분석 (API 불필요)
# 목적: pandyo.json 3개 문서 간 키워드 Jaccard 유사도 계산
# 실행: python test_keyword_overlap.py
# =========================================================
import json
import re
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PANDYO_PATH = os.path.join(BASE_DIR, "..", "json", "pandyo", "pandyo.json")


def extract_keywords(json_data):
    """JSON 데이터에서 의미있는 키워드를 추출"""
    text = json.dumps(json_data) if not isinstance(json_data, str) else json_data

    keywords = set()

    # 1. Action 키워드 추출
    # "Action": ["iam:Get*", ...] 또는 "Action": "sts:AssumeRole"
    action_list_matches = re.findall(r'"Action":\s*\[([^\]]+)\]', text)
    for match in action_list_matches:
        for kw in re.findall(r'"([^"]+)"', match):
            keywords.add(kw)

    action_single_matches = re.findall(r'"Action":\s*"([^"]+)"', text)
    for kw in action_single_matches:
        keywords.add(kw)

    # 2. 노드 타입 추출
    for match in re.findall(r'"type":\s*"([^"]+)"', text):
        keywords.add(f"type:{match}")
    for match in re.findall(r'"node_type":\s*"([^"]+)"', text):
        keywords.add(f"type:{match}")

    # 3. Edge 관계 추출
    for match in re.findall(r'"relation":\s*"([^"]+)"', text):
        keywords.add(f"relation:{match}")

    # 4. 정책 이름 추출
    for match in re.findall(r'"PolicyName":\s*"([^"]+)"', text):
        keywords.add(f"policy:{match}")

    # 5. 서비스 접두사 추출 (Action에서)
    service_prefixes = set()
    for kw in list(keywords):
        if ":" in kw and not kw.startswith(("type:", "relation:", "policy:")):
            service_prefixes.add(f"service:{kw.split(':')[0]}")
    keywords.update(service_prefixes)

    return keywords


def jaccard_similarity(set1, set2):
    """두 집합의 Jaccard 유사도 계산"""
    intersection = set1 & set2
    union = set1 | set2
    return len(intersection) / len(union) if union else 0


def categorize_keywords(keywords):
    """키워드를 카테고리별로 분류"""
    categories = {
        "서비스 타입": set(),
        "Action 권한": set(),
        "Edge 관계": set(),
        "정책 이름": set(),
        "서비스 접두사": set(),
    }
    for kw in keywords:
        if kw.startswith("type:"):
            categories["서비스 타입"].add(kw)
        elif kw.startswith("relation:"):
            categories["Edge 관계"].add(kw)
        elif kw.startswith("policy:"):
            categories["정책 이름"].add(kw)
        elif kw.startswith("service:"):
            categories["서비스 접두사"].add(kw)
        else:
            categories["Action 권한"].add(kw)
    return categories


def main():
    if not os.path.exists(PANDYO_PATH):
        print(f"❌ 파일을 찾을 수 없습니다: {PANDYO_PATH}")
        return

    with open(PANDYO_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 각 문서에서 키워드 추출
    docs = {}
    for item in data:
        title = item["title"]
        keywords = extract_keywords(item["resources"])
        docs[title] = keywords

    # =============================================
    # 1. 각 문서의 키워드 상세 정보
    # =============================================
    print("=" * 70)
    print("📊 [테스트 1] 키워드 오버랩 분석")
    print("=" * 70)

    for title, kws in docs.items():
        categories = categorize_keywords(kws)
        print(f"\n📄 {title} (총 {len(kws)}개 키워드)")
        for cat_name, cat_kws in categories.items():
            if cat_kws:
                print(f"   {cat_name} ({len(cat_kws)}): {sorted(cat_kws)}")

    # =============================================
    # 2. Jaccard 유사도 매트릭스
    # =============================================
    print("\n" + "=" * 70)
    print("📐 Jaccard 유사도 매트릭스")
    print("=" * 70)

    titles = list(docs.keys())
    for i in range(len(titles)):
        for j in range(i + 1, len(titles)):
            t1, t2 = titles[i], titles[j]
            sim = jaccard_similarity(docs[t1], docs[t2])
            common = docs[t1] & docs[t2]
            only_t1 = docs[t1] - docs[t2]
            only_t2 = docs[t2] - docs[t1]

            print(f"\n{'─' * 60}")
            print(f"🔗 {t1} ↔ {t2}")
            print(f"   Jaccard 유사도: {sim:.4f} ({len(common)}/{len(docs[t1] | docs[t2])})")
            print(f"   공통 키워드 ({len(common)}): {sorted(common)}")
            print(f"   {t1} 고유 ({len(only_t1)}): {sorted(only_t1)}")
            print(f"   {t2} 고유 ({len(only_t2)}): {sorted(only_t2)}")

    # =============================================
    # 3. IAM 공통 패턴 비중 분석
    # =============================================
    print("\n" + "=" * 70)
    print("🔍 IAM 공통 패턴 비중 분석")
    print("=" * 70)

    # IAM 공통으로 간주되는 키워드
    iam_common = {
        "sts:AssumeRole", "type:iam_user", "type:iam_role",
        "iam:Get*", "iam:List*", "service:iam", "service:sts",
        "relation:IAM_USER_ACCESS_IAM", "relation:ASSUME_ROLE",
        "relation:IAM_USER_ASSUME_ROLE", "relation:IAM_USER_CAN_ASSUME_ROLE",
    }

    for title, kws in docs.items():
        overlap = kws & iam_common
        ratio = len(overlap) / len(kws) if kws else 0
        print(f"\n📄 {title}")
        print(f"   전체 키워드: {len(kws)}개")
        print(f"   IAM 공통 패턴: {len(overlap)}개 ({ratio:.1%})")
        print(f"   고유 키워드: {len(kws - iam_common)}개 ({1-ratio:.1%})")
        print(f"   IAM 공통: {sorted(overlap)}")

    # =============================================
    # 4. 결론
    # =============================================
    print("\n" + "=" * 70)
    print("📝 분석 결론")
    print("=" * 70)

    # lambda_privesc ↔ iam_privesc vs 나머지 비교
    if len(titles) >= 3:
        pairs = []
        for i in range(len(titles)):
            for j in range(i + 1, len(titles)):
                sim = jaccard_similarity(docs[titles[i]], docs[titles[j]])
                pairs.append((titles[i], titles[j], sim))

        pairs.sort(key=lambda x: x[2], reverse=True)
        print("\n유사도 순위:")
        for rank, (t1, t2, sim) in enumerate(pairs, 1):
            marker = "⚠️" if sim > 0.3 else "✅"
            print(f"  {rank}. {marker} {t1} ↔ {t2}: {sim:.4f}")


if __name__ == "__main__":
    main()
