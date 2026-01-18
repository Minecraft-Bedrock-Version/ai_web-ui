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
    # 1. 컬렉션 생성(컬렉션 중복 생성 방지)
    if not q_client.collection_exists(COLLECTION_NAME):
        q_client.create_collection(  # 새 컬렉션 생성
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=1536, distance=Distance.COSINE), # 1535: cohere v4가 출력하는 차원. COSINE: 의미적 유사도 검색에 가장 적합
        )

    # 2. 취약점 패턴 데이터 로드
    with open("infra_vuln_test.json", "r", encoding="utf-8") as f:
        vuln_data = json.load(f) # json 데이터 로드

    # 3. JSON 구조 그대로 임베딩 및 저장
    points = [] # Qdrant에 넣을 벡터 리스트
    for item in vuln_data:
        print(f"[ID: {item['id']}] '{item['title']}' - Raw JSON 구조 임베딩 중...")
        
        # [핵심] JSON 전체(또는 핵심 resources 부분)를 문자열로 변환
        # indent를 주면 가독성이 좋아져 모델이 계층 구조를 더 잘 파악할 수 있습니다.
        raw_json_data = json.dumps(item, indent=2, ensure_ascii=False) # JSON을 문장화하지 않음. indent=2: json 계층 구조를 잘 인식, ensure_ascii=False: 한글 깨짐 방지
        
        # 모델에 JSON 데이터 전체를 입력 (v4는 이 구조를 학습한 모델임)
        vector = get_embedding(raw_json_data) # json 전체 -> 의미 벡터(리소스 구성, 권한, 서비스 관계 등을 통합 의미 공간으로 압축)
        
        points.append(PointStruct(
            id=item["id"], #고유 식별자
            vector=vector, # 검색용
            payload=item # 원본 데이터 보관
        ))

    # 4. Qdrant 업로드
    q_client.upsert(collection_name=COLLECTION_NAME, points=points) # 동일 id면 덮어씀
    print(f"\n완료. 총 {len(points)}개의 JSON 구조 데이터가 '{COLLECTION_NAME}'에 저장되었습니다.")

if __name__ == "__main__":
    main()