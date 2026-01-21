import boto3
import json
import os
from qdrant_client import QdrantClient

# fastapi 라우터 설정
from fastapi import APIRouter
router = APIRouter()

# --- 경로 설정 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 검색할 대상 파일 (사용자가 방금 올린 JSON 구조)
SEARCH_TARGET_PATH = os.path.join(BASE_DIR, "..", "json", "pandyo", "search_pandyo.json")

# --- 설정 ---
REGION = "ap-northeast-1"
MODEL_ID = "cohere.embed-v4:0"
COLLECTION_NAME = "pandyo"

bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)
q_client = QdrantClient(url="http://localhost:6333")

def get_embedding(text):
    """Bedrock을 통해 데이터 구조를 벡터로 변환"""
    native_request = {
        "texts": [text], 
        "input_type": "search_query", 
        "truncate": "NONE"
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request))
    res_body = json.loads(response.get('body').read())
    embeddings = res_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]

def main():
    try:
        if not os.path.exists(SEARCH_TARGET_PATH):
            print(f"❌ 파일을 찾을 수 없습니다: {SEARCH_TARGET_PATH}")
            return
            
        with open(SEARCH_TARGET_PATH, "r", encoding="utf-8") as f:
            search_data = json.load(f)
        
        # 1. 검색 데이터 가공 (resources 내부의 content만 추출하여 문맥화)
        # JSON의 핵심인 '어떤 리소스가 있고 어떤 상태인지'를 보존하여 텍스트로 만듭니다.
        if "resources" in search_data:
            # resources 리스트에서 각 파일의 내용(content)만 합칩니다.
            context_list = [res.get("content", {}) for res in search_data["resources"]]
            query_text = json.dumps(context_list, ensure_ascii=False)
        else:
            # resources 구조가 아닐 경우 전체를 사용
            query_text = json.dumps(search_data, ensure_ascii=False)

        print(f"🔎 인프라 구조 분석 중... (데이터 길이: {len(query_text)})")

        # 2. 벡터 검색 수행
        query_vector = get_embedding(query_text)
        search_response = q_client.query_points(
            collection_name=COLLECTION_NAME,
            query=query_vector,
            limit=3
        )
        
        # 3. 결과 출력
        results = search_response.points
        if results:
            print("\n" + "="*30 + " 검색 결과 " + "="*30)
            for i, hit in enumerate(results):
                p = hit.payload
                print(f"[{i+1}위] {p.get('title')} | 유사도: {hit.score:.4f}")
                print(f"📌 취약점 설명: {p.get('description')}")
                print("-" * 71)
        else:
            print("❌ 매칭되는 취약점 패턴을 찾지 못했습니다.")

    except Exception as e:
        print(f"❌ 오류 발생: {e}")

if __name__ == "__main__":
    main()