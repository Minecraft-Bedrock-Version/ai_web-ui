"""
EC2 핸들러

EC2 인스턴스 및 관련 리소스에 대한 AWS CLI 명령어를 생성합니다.
리전별 SSM Parameter를 사용하여 최신 AMI를 자동으로 해결합니다.
"""

from .base_handler import BaseHandler


class EC2Handler(BaseHandler):
    """EC2 관련 AWS CLI 명령어를 생성하는 핸들러입니다."""
    
    @property
    def service_name(self) -> str:
        return "ec2"
    
    # OS/버전/아키텍처별 SSM Parameter Path 매핑
    # 어느 리전에서든 해당 리전의 최신 AMI ID를 자동으로 가져옵니다.
    SSM_PARAM_MAP = {
        "amazon-linux": {
            "2023": {
                "x86_64": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
                "arm64": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
            },
            "2": {
                "x86_64": "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2",
                "arm64": "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-arm64-gp2"
            }
        },
        "ubuntu": {
            "24.04": {
                "x86_64": "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
                "arm64": "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
            },
            "22.04": {
                "x86_64": "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
                "arm64": "/aws/service/canonical/ubuntu/server/22.04/stable/current/arm64/hvm/ebs-gp2/ami-id"
            },
            "20.04": {
                "x86_64": "/aws/service/canonical/ubuntu/server/20.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
                "arm64": "/aws/service/canonical/ubuntu/server/20.04/stable/current/arm64/hvm/ebs-gp2/ami-id"
            }
        }
    }

    def generate_commands(self, state: dict, region: str = None) -> str:
        """
        EC2 리소스를 위한 AWS CLI 명령어를 생성합니다.
        
        Args:
            state: EC2 구성 정보
            region: AWS 리전 (예: "ap-northeast-1")
        
        Returns:
            str: 생성된 AWS CLI 명령어
        """
        # 프론트엔드에서 넘어오는 데이터 구조에 맞춰 추출
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
        
        # 1. SSM Parameter Path 결정 (리전에 관계없이 최신 AMI 자동 해결)
        ssm_path = self.SSM_PARAM_MAP.get(os_type, {}).get(os_version, {}).get(arch)
        
        if not ssm_path:
            # 매핑이 없는 경우 기본 Amazon Linux 2023 경로 사용
            ssm_path = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

        # 2. run-instances 명령어 조립
        cmd = "aws ec2 run-instances"
        
        # 리전 옵션 추가 (프론트엔드에서 전달된 경우)
        if region:
            cmd += f" --region {region}"
        
        # AMI ID (SSM Parameter resolve 방식)
        cmd += f" --image-id resolve:ssm:{ssm_path}"
        
        # 인스턴스 타입
        cmd += f" --instance-type {instance_type}"
        
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
            cmd += ' --metadata-options "HttpTokens=required"'
        
        # 암호화 설정 (EBS 볼륨)
        if encrypted == "true":
            cmd += " --block-device-mappings '[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"Encrypted\":true}}]'"

        commands.append(cmd)
        
        return "\n".join(commands)
