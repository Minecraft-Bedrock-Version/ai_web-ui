# db 저장용 테스트 코드(임베딩+저장)
import boto3 # bedrock API 호출을 위해 사용
import json
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

# --- 설정 ---
REGION = "ap-northeast-1" # 도쿄 리전
MODEL_ID = "cohere.embed-v4:0" # 임베딩 모델
COLLECTION_NAME = "json_test" # 데이터를 저장할 컬렉션 이름

bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION) # bedrock 전용 클라이언트
q_client = QdrantClient(url="http://localhost:6333") # Qdrant 인스턴스에 연결

# --임베딩 함수--
def get_embedding(text):
    """JSON 구조 문자열을 1536차원 벡터로 변환"""
    native_request = {
        "texts": [text], # cohere v4는 배열->단일 텍스트도 리스트로 감싸야 함
        "input_type": "search_document", # 역할 명시 -> db에 저장될 문서
        "truncate": "NONE" # 입력 값이 길어도 자르지 말 것. 너무 크면 토큰 제한 에러날 수도
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request)) #bedrock 모델 실행. body는 json
    response_body = json.loads(response.get('body').read())
    embeddings = response_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0] # 응답이 dict면 "float"키에서 첫 벡터, list면 첫 벡터

def main():
    # 1. 컬렉션 생성 (동일)
    if not q_client.collection_exists(COLLECTION_NAME):
        q_client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=1536, distance=Distance.COSINE),
        )

    # 2. 데이터 로드
    with open("./json/infra_vuln_test.json", "r", encoding="utf-8") as f:
        vuln_data = json.load(f)

    # 3. resources 필드 원본 그대로 임베딩 및 저장
    points = []
    for item in vuln_data:
        print(f"[ID: {item['id']}] '{item['title']}' - 'resources' 원본 임베딩 중...")
        
        # [핵심] 전처리 없이 resources 필드의 데이터를 그대로 가져옴
        target_resources = item.get("resources", [])
        
        # [핵심] 리스트 구조 그대로 JSON 문자열 변환 (가공 없음)
        raw_resources_str = json.dumps(target_resources, indent=2, ensure_ascii=False)
        
        # 모델에 resources 원본 데이터 전달
        vector = get_embedding(raw_resources_str)
        
        points.append(PointStruct(
            id=item["id"], 
            vector=vector, 
            payload=item # 원본 전체 데이터 보관
        ))

    # 4. Qdrant 업로드
    q_client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"\n완료. 총 {len(points)}개의 데이터가 저장되었습니다.")

if __name__ == "__main__":
    main()