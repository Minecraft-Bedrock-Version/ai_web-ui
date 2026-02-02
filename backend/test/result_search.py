import boto3
import json
import os
from qdrant_client import QdrantClient

# --- 경로 설정 (사진의 backend/test/ 구조 기준) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 같은 폴더(test)에 있는 local_debug_result.json 탐지
SEARCH_TARGET_PATH = os.path.join(BASE_DIR, "sqs_flag_shop.json")

# --- 설정 ---
REGION = "ap-northeast-1"
MODEL_ID = "cohere.embed-v4:0"
COLLECTION_NAME = "pandyo"

bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)
q_client = QdrantClient(url="http://localhost:6333")

def get_embedding(text):
    """Bedrock을 통해 텍스트를 벡터로 변환"""
    native_request = {
        "texts": [text], 
        "input_type": "search_query", 
        "truncate": "NONE"
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request))
    res_body = json.loads(response.get('body').read())
    embeddings = res_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]

def run_local_debug_search():
    print(f"🚀 디버깅 시작: {SEARCH_TARGET_PATH} 파일 분석 중...")

    try:
        # 1. 파일 존재 여부 확인
        if not os.path.exists(SEARCH_TARGET_PATH):
            print(f"❌ 파일을 찾을 수 없습니다: {SEARCH_TARGET_PATH}")
            return
            
        with open(SEARCH_TARGET_PATH, "r", encoding="utf-8") as f:
            search_data = json.load(f)
        
        # 2. 데이터 가공 (resources 내부 content 추출)
        if "resources" in search_data:
            context_list = [res.get("content", {}) for res in search_data["resources"]]
            query_text = json.dumps(context_list, ensure_ascii=False)
        else:
            query_text = json.dumps(search_data, ensure_ascii=False)

        # 3. 벡터 검색 수행 (상위 3개 추출)
        query_vector = get_embedding(query_text)
        search_response = q_client.query_points(
            collection_name=COLLECTION_NAME,
            query=query_vector,
            limit=3  # 상위 3위까지 추출
        )
        
        # 4. 결과 출력
        results = search_response.points

        if results:
            print("\n" + "="*20 + " [유사도 Top 3 결과] " + "="*20)
            for i, hit in enumerate(results):
                p = hit.payload
                score = hit.score
                title = p.get('title', '제목 없음')
                desc = p.get('description', '설명 없음')
                
                # 가독성을 위한 출력
                print(f"[{i+1}위] 점수: {score:.4f}")
                print(f"🔹 취약점명: {title}")
                print(f"📌 상세설명: {desc[:100]}...") # 너무 길면 생략
                print("-" * 60)
        else:
            print("❌ Qdrant에서 매칭되는 결과를 찾지 못했습니다.")

    except Exception as e:
        print(f"❌ 오류 발생: {e}")

if __name__ == "__main__":
    run_local_debug_search()