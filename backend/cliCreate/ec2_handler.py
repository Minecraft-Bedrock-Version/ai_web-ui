"""
EC2 핸들러

EC2 인스턴스 및 관련 리소스에 대한 AWS CLI 명령어를 생성합니다.
"""

from .base_handler import BaseHandler


class EC2Handler(BaseHandler):
    """EC2 관련 AWS CLI 명령어를 생성하는 핸들러입니다."""
    
    @property
    def service_name(self) -> str:
        return "ec2"
    
    # OS별 AMI 매핑 (서울 리전 기준 예시)
    AMI_MAP = {
        "amazon-linux": {
            "2023": {
                "x86_64": "ami-0c0b8e92e5e1d3f9e", # Amazon Linux 2023 AMI
                "arm64": "ami-0a2569f1025732168"
            },
            "2": {
                "x86_64": "ami-04cf8941fc226689d", # Amazon Linux 2 AMI
                "arm64": "ami-0c7f8f9426fcd9f5a"
            }
        },
        "ubuntu": {
            "24.04": {
                "x86_64": "ami-040c33c6a51fd5d96",
                "arm64": "ami-07973030383182b8d"
            },
            "22.04": {
                "x86_64": "ami-0c4667a98848f3223",
                "arm64": "ami-095a5f15d5fddcf41"
            },
            "20.04": {
                "x86_64": "ami-0e1ce011666e864b2",
                "arm64": "ami-0bc30263f31742918"
            }
        }
    }

    def generate_commands(self, state: dict) -> str:
        """
        EC2 리소스를 위한 AWS CLI 명령어를 생성합니다.
        
        Args:
            state: EC2 구성 정보
        """
        # 프론트엔드에서 넘어오는 데이터 구조에 맞춰 추출
        resource_type = "instance" # 현재는 인스턴스 생성만 지원
        
        name = state.get("name", "my-instance")
        os_type = state.get("os", "amazon-linux")
        os_version = state.get("osVersion", "2023")
        arch = state.get("arch", "x86_64")
        instance_type = state.get("instanceType", "t3.micro")
        public_ip = state.get("publicIp", "true")
        keypair = state.get("keypair", "없음")
        imds = state.get("imds", "optional")
        encrypted = state.get("encrypted", "true")
        
        commands = []
        
        # 1. AMI ID 결정
        ami_id = "ami-xxxxxxxxxxxxxxxxx" # 기본값
        try:
            ami_id = self.AMI_MAP.get(os_type, {}).get(os_version, {}).get(arch, ami_id)
        except Exception:
            pass

        # 2. run-instances 명령어 조립
        cmd = f"aws ec2 run-instances --image-id {ami_id} --instance-type {instance_type}"
        
        # 태그 설정 (이름)
        cmd += f" --tag-specifications 'ResourceType=instance,Tags=[{{Key=Name,Value={name}}}]'"
        
        # 키 페어
        if keypair != "없음":
            cmd += f" --key-name {keypair}"
        
        # 퍼블릭 IP 설정
        if public_ip == "true":
            cmd += " --associate-public-ip-address"
        else:
            cmd += " --no-associate-public-ip-address"
            
        # IMDS 설정
        if imds == "required":
            cmd += " --metadata-options \"HttpTokens=required\""
        
        # 암호화 (간단하게 플래그로 표현, 실제로는 BlockDeviceMappings 필요)
        if encrypted == "true":
            # 실제 AWS CLI에서는 블록 디바이스 매핑에서 설정해야 하지만, 
            # 시각화/데모용으로 간단한 형태를 유지하거나 주석을 달 수 있습니다.
            pass

        commands.append(cmd)
        
        return "\n".join(commands)
