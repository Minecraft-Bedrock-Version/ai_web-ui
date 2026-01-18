# 검색용 테스트 코드(임베딩+검색결과)
import boto3
import json
from qdrant_client import QdrantClient

# --- 설정 (이전과 동일) ---
REGION = "ap-northeast-1"
MODEL_ID = "cohere.embed-v4:0"
COLLECTION_NAME = "json_test"

bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)
q_client = QdrantClient(url="http://localhost:6333")

def get_embedding(text):
    """Bedrock을 통해 검색 쿼리용 벡터 생성"""
    native_request = {"texts": [text], "input_type": "search_query", "truncate": "NONE"}
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request))
    res_body = json.loads(response.get('body').read())
    
    # v4 응답 구조 처리
    embeddings = res_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]

def main():
    # 1. search_test_infra.json 파일 로드
    try:
        with open("search_test_infra.json", "r", encoding="utf-8") as f:
            test_infra = json.load(f)
        print("📄 'search_test_infra.json' 파일을 성공적으로 읽어왔습니다.")
    except FileNotFoundError:
        print("❌ 'search_test_infra.json' 파일이 없습니다. 파일을 먼저 생성해 주세요.")
        return
    except json.JSONDecodeError:
        print("❌ JSON 파일 형식이 올바르지 않습니다.")
        return

    # 2. 테스트용 JSON을 통째로 임베딩 (저장할 때와 동일한 방식으로 문자열화)
    # indent=2를 주어 구조적 특징을 모델이 잘 파악하도록 합니다.
    query_text = json.dumps(test_infra, indent=2, ensure_ascii=False)
    query_vector = get_embedding(query_text)

    # 3. Qdrant 검색 실행
    print("🔍 벡터 DB에서 가장 유사한 취약점 구조를 검색 중...")
    search_response = q_client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=1
    )
    
    result = search_response.points

    # 4. 결과 출력
    if result:
        hit = result[0]
        p = hit.payload
        print("-" * 50)
        print(f"✅ 검색 성공! 가장 유사한 취약점: {p.get('title')}")
        print(f"📊 유사도 점수: {hit.score:.4f}")
        print(f"📝 상세 설명: {p.get('description')}")
        print("-" * 50)
    else:
        print("❌ 매칭되는 데이터를 찾지 못했습니다.")

if __name__ == "__main__":
    main()