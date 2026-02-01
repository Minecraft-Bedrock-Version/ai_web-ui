"""
기본 핸들러 추상 클래스

모든 서비스별 CLI 핸들러는 이 클래스를 상속받아야 합니다.
"""

from abc import ABC, abstractmethod


class BaseHandler(ABC):
    """
    CLI 명령어 핸들러를 위한 기본 틀(추상 클래스)입니다.
    
    모든 서비스 핸들러는 다음 두 가지를 반드시 구현해야 합니다:
    1. service_name: 서비스 이름 (예: "iam", "ec2")
    2. generate_commands: 명령어 생성 함수
    """
    
    @property
    @abstractmethod
    def service_name(self) -> str:
        """
        서비스 식별자(이름)를 반환합니다.
        핸들러 레지스트리가 이 이름을 보고 요청을 연결해줍니다.
        
        Returns:
            str: 서비스 이름 (예: "iam", "ec2", "s3")
        """
        pass
    
    @abstractmethod
    def generate_commands(self, state: dict) -> str:
        """
        프론트엔드에서 받은 정보(state)를 바탕으로 AWS CLI 명령어를 생성합니다.
        
        Args:
            state: 프론트엔드 구성 데이터
        
        Returns:
            str: 생성된 AWS CLI 명령어 (줄바꿈으로 구분)
        """
        pass
