"""
CLI 생성 라우터

AWS CLI 명령어를 생성해주는 메인 API 입니다.
핸들러 패턴을 사용하여 다양한 AWS 서비스를 지원할 수 있습니다.
"""

from fastapi import Request, APIRouter, HTTPException
from .handler_registry import get_handler, list_available_services

# FastAPI 라우터 설정
router = APIRouter()


@router.post("/cli_create")
async def cli_create(request: Request):
    """
    AWS CLI 명령어 생성 API 엔드포인트
    
    요청 본문(Body) 예시:
        {
            "state": {
                "service": "iam",           # 서비스 종류 (기본값: "iam")
                "resource": "user",         # 리소스 종류
                "selectedEntity": "name",   # 리소스 이름
                "activePolicies": {...}     # 정책 설정
            }
        }
    
    응답 예시:
        {
            "message": "CLI 생성완료",
            "cli": "aws iam create-user...",  # 생성된 명령어
            "state_echo": {...}
        }
    """
    data = await request.json()
    print("cli_create 함수가 호출되었습니다.")
    print("받은 데이터:", data)
    
    state = data.get("state")
    if not state:
        raise HTTPException(status_code=400, detail="'state' 필드가 필요합니다.")
    
    print("받은 상태(state):", state)
    
    # 서비스 타입 결정 (없으면 "iam"을 기본값으로 사용)
    service = state.get("service", "iam")
    
    try:
        # 1. 해당 서비스를 담당하는 핸들러를 가져옵니다.
        handler = get_handler(service)
        
        # 2. 핸들러에게 명령어를 만들어달라고 시킵니다.
        cli_commands = handler.generate_commands(state)
        
        response = {
            "message": "CLI 생성완료",
            "cli": cli_commands,
            "state_echo": state,
            "service": service
        }
        
        return response
        
    except ValueError as e:
        # 지원하지 않는 서비스를 요청했을 때
        available = list_available_services()
        raise HTTPException(
            status_code=400,
            detail=f"지원하지 않는 서비스입니다: {service}. 가능한 서비스: {available}"
        )
    except Exception as e:
        # 기타 예상치 못한 에러
        print(f"명령어 생성 중 오류 발생: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"CLI 명령어 생성 실패: {str(e)}"
        )