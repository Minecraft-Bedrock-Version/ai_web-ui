import boto3
import json
import os  # 경로 계산을 위해 추가
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

# Request 임포트
from fastapi import Request 

# fastapi 라우터 설정
from fastapi import APIRouter
router = APIRouter()


'''
# --- 경로 자동 설정 (추가된 핵심 로직) ---
# 1. 이 파일(mbv_embed.py)의 실제 위치를 절대 경로로 가져옵니다.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. 파일 위치를 기준으로 json 파일의 절대 경로를 생성합니다.
# mbv_embed.py 위치에서 한 단계 위(..)로 가서 json/pandyo/pandyo.json으로 이동
JSON_FILE_PATH = os.path.join(BASE_DIR, "..", "json", "pandyo", "pandyo.json")

# --- 설정 ---
REGION = "ap-northeast-1"
MODEL_ID = "cohere.embed-v4:0"
COLLECTION_NAME = "pandyo"

bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)
q_client = QdrantClient(url="http://localhost:6333")

def get_embedding(text):
    """JSON 구조 문자열을 1536차원 벡터로 변환"""
    native_request = {
        "texts": [text],
        "input_type": "search_document",
        "truncate": "NONE"
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request))
    response_body = json.loads(response.get('body').read())
    embeddings = response_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]
'''
@router.post("/mbv_embed")
async def mbv_embed(request: Request):
    '''
    # 1. 컬렉션 생성
    if not q_client.collection_exists(COLLECTION_NAME):
        q_client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=1536, distance=Distance.COSINE),
        )

    # 2. 데이터 로드 (수정된 절대 경로 사용)
    if not os.path.exists(JSON_FILE_PATH):
        print(f"에러: 파일을 찾을 수 없습니다 -> {JSON_FILE_PATH}")
        return

    with open(JSON_FILE_PATH, "r", encoding="utf-8") as f:
        vuln_data = json.load(f)

    # 3. 데이터 처리 및 임베딩
    points = []
    for item in vuln_data:
        print(f"[ID: {item['id']}] '{item['title']}' - 임베딩 중...")
        
        target_resources = item.get("resources", [])
        raw_resources_str = json.dumps(target_resources, indent=2, ensure_ascii=False)
        
        vector = get_embedding(raw_resources_str)
        
        points.append(PointStruct(
            id=item["id"], 
            vector=vector, 
            payload=item
        ))

    # 4. Qdrant 업로드
    q_client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"\n완료. 총 {len(points)}개의 데이터가 저장되었습니다.")
'''
    body = await request.json()   # 🔥 여기서 받음
    print("mbv_embed 호출됨: ",body)

    step = body.get("step")
    return {"status": "ok", "received":{
        "step": step
    }}