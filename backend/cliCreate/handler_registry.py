"""
핸들러 레지스트리 (관리자)

작성된 핸들러들을 자동으로 찾아서 등록해주는 관리자입니다.
새로운 핸들러 파일(예: ec2_handler.py)만 만들면 알아서 인식합니다.
"""

import importlib
import inspect
from pathlib import Path
from typing import Dict
from .base_handler import BaseHandler


class HandlerRegistry:
    """
    CLI 명령어 핸들러 저장소입니다.
    현재 폴더에 있는 모든 *_handler.py 파일을 찾아서 자동으로 등록합니다.
    """
    
    def __init__(self):
        self._handlers: Dict[str, BaseHandler] = {}
        self._discover_handlers()
    
    def _discover_handlers(self):
        """
        현재 디렉토리를 스캔하여 자동으로 핸들러를 찾아 등록합니다.
        """
        # 현재 파일이 있는 디렉토리
        current_dir = Path(__file__).parent
        
        # 현재 디렉토리의 모든 .py 파일 탐색
        for file_path in current_dir.glob("*_handler.py"):
            # base_handler.py는 추상 클래스이므로 제외
            if file_path.name == "base_handler.py":
                continue
            
            # 모듈 이름 (확장자 제외)
            module_name = file_path.stem
            
            try:
                # 모듈 동적 임포트 (예: from . import iam_handler)
                module = importlib.import_module(f".{module_name}", package="backend.cliCreate")
                
                # 모듈 내의 모든 클래스 검사
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # BaseHandler를 상속받았는지 확인 (BaseHandler 자체는 제외)
                    if (issubclass(obj, BaseHandler) and 
                        obj is not BaseHandler and
                        hasattr(obj, 'service_name')):
                        
                        # 핸들러 인스턴스(객체) 생성 및 등록
                        handler_instance = obj()
                        service_name = handler_instance.service_name
                        self._handlers[service_name] = handler_instance
                        print(f"[OK] 핸들러 등록 완료: {service_name} ({name})")
                        
            except Exception as e:
                print(f"[WARNING] 핸들러 로딩 실패 ({module_name}): {e}")
    
    def get_handler(self, service: str) -> BaseHandler:
        """
        서비스 이름에 맞는 핸들러를 찾아줍니다.
        
        Args:
            service: 서비스 이름 (예: "iam", "ec2", "s3")
        
        Returns:
            BaseHandler: 해당 서비스의 핸들러
        
        Raises:
            ValueError: 등록되지 않은 서비스를 요청했을 때
        """
        if service not in self._handlers:
            available = ", ".join(self._handlers.keys())
            raise ValueError(
                f"'{service}' 서비스를 처리할 핸들러가 없습니다. "
                f"현재 가능한 서비스: {available}"
            )
        
        return self._handlers[service]
    
    def list_services(self) -> list:
        """
        현재 등록된 모든 서비스 목록을 반환합니다.
        """
        return list(self._handlers.keys())


# 전역 레지스트리 인스턴스 (싱글톤 패턴)
# 프로그램 실행 시 한 번만 만들어져서 계속 사용됩니다.
_registry = HandlerRegistry()


def get_handler(service: str) -> BaseHandler:
    """
    외부에서 핸들러를 쉽게 가져오기 위한 헬퍼 함수입니다.
    
    Args:
        service: 서비스 이름 (예: "iam")
    """
    return _registry.get_handler(service)


def list_available_services() -> list:
    """
    외부에서 가능한 서비스 목록을 쉽게 보기 위한 헬퍼 함수입니다.
    """
    return _registry.list_services()
