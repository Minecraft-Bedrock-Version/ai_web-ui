# 벡터DB 검색용 임베딩
import boto3
import json
import os
from qdrant_client import QdrantClient


# Request 임포트
from fastapi import Request 

# fastapi 라우터 설정
from fastapi import APIRouter
router = APIRouter()

# mbv_llm_gpt.py 임포트
from backend.llm.mbv_llm_gpt import run_mbv_llm

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


# 임베딩 함수
def get_embedding(text):
    """Bedrock을 통해 데이터 구조를 벡터로 변환"""
    native_request = {
        "texts": [text], 
        "input_type": "search_query", 
        "truncate": "NONE"
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request)) # 임베딩
    res_body = json.loads(response.get('body').read())
    embeddings = res_body.get('embeddings') # 임베딩 값
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]


@router.post("/mbv_search")
async def mbv_search(request: Request):
    print("mbv_search 함수 실행됨")

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

        # 2. 벡터 검색 수행 (유사도 ≥ 0.7 인 문서 전부 수집)
        SIMILARITY_THRESHOLD = 0.7
        query_vector = get_embedding(query_text)
        search_response = q_client.query_points(
            collection_name=COLLECTION_NAME,
            query=query_vector,
            limit=10
        )
        
        # 3. 유사도 필터링 및 결과 출력
        results = search_response.points

        # 유사도 ≥ 0.7 인 문서만 필터링
        qualified_docs = [hit for hit in results if hit.score >= SIMILARITY_THRESHOLD]

        print("\n" + "="*30 + " 검색 결과 " + "="*30)
        print(f"📊 전체 결과: {len(results)}건 | 유사도 ≥ {SIMILARITY_THRESHOLD}: {len(qualified_docs)}건")

        for i, hit in enumerate(results):
            p = hit.payload
            marker = "✅" if hit.score >= SIMILARITY_THRESHOLD else "❌"
            print(f"  {marker} [{i+1}위] {p.get('title')} | 유사도: {hit.score:.4f} | 경로: {p.get('description')}")
        print("-" * 71)

        if not qualified_docs:
            print(f"⚠️ 유사도 ≥ {SIMILARITY_THRESHOLD} 인 문서가 없습니다.")
            print("  탐지된 취약점이 없습니다.")
            return {"infrastructure": search_data, "analysis": 1}

        # 4. 매칭 문서 경로 리스트 구성 → mbv_llm_gpt 로 전달
        doc_paths = [
            (hit.payload.get("description", ""), hit.payload.get("title", "unknown"), hit.score)
            for hit in qualified_docs
        ]

        print(f"\n📄 LLM 에 전달할 문서 {len(doc_paths)}건:")
        for i, (path, title, score) in enumerate(doc_paths, 1):
            print(f"  [{i}] {title} (유사도: {score:.4f}) → {path}")

        analysis_result = {"error": "분석이 실행되지 않음."}

        print("\nrun_mbv_llm 실행 시작")
        analysis_result = run_mbv_llm(doc_paths)
        print("run_mbv_llm 실행 완료")

        print("LLM 분석 결과:", analysis_result)

        return {"infrastructure": search_data, "analysis": analysis_result}

    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        return {"error": str(e)}