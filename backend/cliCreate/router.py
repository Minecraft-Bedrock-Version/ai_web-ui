"""
CLI 도구 통합 라우터

cliCreate 모듈의 모든 라우터를 한 곳에 모아서 관리합니다.
새로운 라우터를 추가할 때는 이 파일만 수정하면 됩니다.
"""

from fastapi import APIRouter
from .cliCreate import router as cli_create_router
from .list import router as list_router

# CLI 도구 메인 라우터
router = APIRouter(
    tags=["CLI Tools"]
)

# 서브 라우터들을 통합
router.include_router(cli_create_router)
router.include_router(list_router)

# 향후 추가 예시:
# from .ec2Create import router as ec2_create_router
# router.include_router(ec2_create_router)
