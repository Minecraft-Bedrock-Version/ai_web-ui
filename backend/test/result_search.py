import boto3
import json
import os
import glob
from qdrant_client import QdrantClient

# =================================================================
# 1. 환경 설정 및 경로 탐색
# =================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 대상 파일: sqs_flag_shop으로 시작하는 모든 JSON
SEARCH_PATTERN = os.path.join(BASE_DIR, "lambda_privesc*.json")

REGION = "ap-northeast-1"
MODEL_ID = "cohere.embed-v4:0"
COLLECTION_NAME = "pandyo"

# 클라이언트 초기화
bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)
q_client = QdrantClient(url="http://localhost:6333")

# =================================================================
# 2. 벡터 변환 함수
# =================================================================

def get_embedding(text):
    """입력받은 텍스트 전체를 Bedrock을 통해 벡터로 변환"""
    native_request = {
        "texts": [text], 
        "input_type": "search_query", 
        "truncate": "NONE"
    }
    
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request))
    res_body = json.loads(response.get('body').read())
    embeddings = res_body.get('embeddings')
    
    # 모델 응답 구조에 맞게 첫 번째 벡터값 반환
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]

# =================================================================
# 3. 메인 실행 반복문
# =================================================================

def run_local_debug_search():
    # 파일명 순서대로 리스트업
    file_list = sorted(glob.glob(SEARCH_PATTERN))
    
    if not file_list:
        print(f"❗ [에러] '{SEARCH_PATTERN}' 패턴의 파일을 찾을 수 없습니다.")
        return

    print(f"🚀 총 {len(file_list)}개의 파일을 순차적으로 분석합니다 (전체 데이터 모드).")

    for target_file in file_list:
        file_name = os.path.basename(target_file)
        print(f"\n📂 파일 분석 중: {file_name}")

        try:
            # [핵심] 정제 없이 파일 내용 전체를 텍스트로 읽어옴
            with open(target_file, "r", encoding="utf-8") as f:
                query_text = f.read() 

            # 1. 전체 텍스트 임베딩
            query_vector = get_embedding(query_text)

            # 2. Qdrant 검색 (가장 유사한 Top 3)
            search_response = q_client.query_points(
                collection_name=COLLECTION_NAME,
                query=query_vector,
                limit=3
            )
            
            # 3. 결과 출력
            print("=" * 60)
            if search_response.points:
                for i, hit in enumerate(search_response.points):
                    score = hit.score
                    title = hit.payload.get('title', '제목 없음')
                    print(f"[{i+1}위] 점수: {score:.4f} | 정책명: {title}")
            else:
                print("❌ 매칭되는 결과를 찾지 못했습니다.")
            print("=" * 60)

        except Exception as e:
            print(f"❌ {file_name} 분석 중 오류 발생: {e}")

if __name__ == "__main__":
    run_local_debug_search()