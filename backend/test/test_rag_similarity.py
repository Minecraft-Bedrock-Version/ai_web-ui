#!/usr/bin/env python3
"""
==========================================================
RAG 유사도 검증 테스트
==========================================================
목적: 사용자 제공 인프라 JSON에 대해 Qdrant 벡터 검색을 수행하여
      iam_privesc_by_key_rotation과 eventbridge_target이
      가장 높은 유사도로 반환되는지 확인
"""

import json
import boto3
from qdrant_client import QdrantClient
from datetime import datetime

# --- 설정 ---
REGION = "ap-northeast-1"
MODEL_ID = "cohere.embed-v4:0"
COLLECTION_NAME = "pandyo"

bedrock = boto3.client(service_name='bedrock-runtime', region_name=REGION)
q_client = QdrantClient(url="http://localhost:6333")

# 테스트 대상 인프라 JSON (사용자 제공)
TARGET_INFRA = {
  "schema_version": "1.5",
  "nodes": [
    {
      "node_id": "288528695623:iam_user:even",
      "type": "iam_user",
      "name": "even",
      "properties": {
        "inline_policies": [
          {
            "Effect": "Allow",
            "Action": [
              "lambda:ListFunctions",
              "lambda:GetFunction",
              "events:PutTargets",
              "events:PutRule",
              "iam:List*",
              "iam:Get*",
              "iam:CreateAccessKey"
            ],
            "Resource": "*"
          }
        ],
        "attached_policies": [],
        "group_policies": []
      }
    },
    {
      "node_id": "288528695623:iam_role:admin_secrets",
      "type": "iam_role",
      "name": "admin_secrets",
      "properties": {
        "assume_role_policy": {
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "sts:AssumeRole",
              "Principal": {
                "AWS": "arn:aws:iam::288528695623:user/admin_mbv"
              }
            }
          ]
        },
        "inline_policies": [
          {
            "PolicyName": "secretsmanager",
            "Statement": [
              {
                "Action": [
                  "secretsmanager:ListSecrets",
                  "secretsmanager:GetSecretValue"
                ],
                "Effect": "Allow",
                "Resource": ["*"]
              }
            ]
          }
        ],
        "attached_policies": []
      }
    },
    {
      "node_id": "288528695623:iam_role:lambda-role-mbv",
      "type": "iam_role",
      "name": "lambda-role-mbv",
      "properties": {
        "assume_role_policy": {
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "sts:AssumeRole",
              "Principal": {
                "Service": "lambda.amazonaws.com"
              }
            }
          ]
        },
        "inline_policies": [],
        "attached_policies": [
          {
            "PolicyName": "lambda-policy-mbv",
            "Statement": [
              {
                "Action": ["cloudtrail:LookupEvents"],
                "Effect": "Allow",
                "Resource": "*"
              },
              {
                "Action": ["iam:AttachUserPolicy"],
                "Effect": "Allow",
                "Resource": "*"
              },
              {
                "Action": [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents"
                ],
                "Effect": "Allow",
                "Resource": "arn:aws:logs:*:*:*"
              }
            ]
          }
        ]
      }
    },
    {
      "node_type": "secretsmanager",
      "node_id": "288528695623:us-east-1:secretsmanager:secret_key"
    },
    {
      "node_id": "288528695623:iam_user:admin_mbv",
      "type": "iam_user",
      "name": "admin_mbv",
      "properties": {
        "inline_policies": [],
        "attached_policies": [
          {
            "Effect": "Allow",
            "Action": ["sts:AssumeRole", "iam:List*", "iam:Get*"],
            "Resource": "*"
          }
        ],
        "group_policies": []
      }
    },
    {
      "node_id": "288528695623:us-east-1:eventbridge:iam_taguser",
      "type": "eventbridge",
      "name": "iam_taguser",
      "attributes": {
        "state": "ENABLED",
        "target_arn": [
          "arn:aws:lambda:us-east-1:288528695623:function:tag-lambda-mbv"
        ]
      }
    },
    {
      "node_id": "288528695623:us-east-1:lambda:tag-lambda-mbv",
      "type": "lambda",
      "name": "tag-lambda-mbv",
      "properties": {
        "event_source_arn": []
      }
    }
  ],
  "edges": [
    {
      "id": "edge:tag-lambda-mbv:ASSUMES_ROLE:lambda-role-mbv",
      "src": "288528695623:us-east-1:lambda:tag-lambda-mbv",
      "dst": "288528695623:iam_role:lambda-role-mbv",
      "relation": "LAMBDA_ASSUMES_ROLE",
      "directed": True,
      "conditions": "This Lambda function executes with the permissions of lambda-role-mbv role."
    },
    {
      "id": "edge:even:IAM_USER_MANAGE_EVENTBRIDGE:iam_taguser",
      "src": "288528695623:iam_user:even",
      "dst": "288528695623:us-east-1:eventbridge:iam_taguser",
      "relation": "IAM_USER_MANAGE_EVENTBRIDGE",
      "directed": True,
      "conditions": "User can modify EventBridge rules to redirect triggers."
    },
    {
      "id": "edge:even:IAM_USER_CREATE_USER_ACCESSKEY:admin_mbv",
      "src": "288528695623:iam_user:even",
      "dst": "288528695623:iam_user:admin_mbv",
      "relation": "IAM_USER_CREATE_USER_ACCESSKEY",
      "directed": True,
      "conditions": "This user can generate access keys for other users."
    },
    {
      "id": "edge:admin_secrets:IAM_ROLE_ACCESS_SECRETSMANAGER:secret_key",
      "src": "288528695623:iam_role:admin_secrets",
      "dst": "288528695623:us-east-1:secretsmanager:secret_key",
      "relation": "IAM_ROLE_ACCESS_SECRETSMANAGER",
      "directed": True,
      "conditions": "This role gives you access to Secrets Manager."
    },
    {
      "id": "edge:even:IAM_USER_ACCESS_LAMBDA:tag-lambda-mbv",
      "src": "288528695623:iam_user:even",
      "dst": "288528695623:us-east-1:lambda:tag-lambda-mbv",
      "relation": "IAM_USER_ACCESS_LAMBDA",
      "directed": True,
      "conditions": "This User has access to Lambda."
    },
    {
      "id": "edge:iam_taguser:TRIGGERS:tag-lambda-mbv",
      "src": "288528695623:us-east-1:eventbridge:iam_taguser",
      "dst": "288528695623:us-east-1:lambda:tag-lambda-mbv",
      "relation": "EVENTBRIDGE_TRIGGERS_LAMBDA",
      "directed": True,
      "conditions": "Rule triggers this Lambda. Attackers can modify 'Input' to exploit it."
    },
    {
      "id": "edge:admin_mbv:ASSUME_ROLE:admin_secrets",
      "src": "288528695623:iam_user:admin_mbv",
      "dst": "288528695623:iam_role:admin_secrets",
      "relation": "ASSUME_ROLE",
      "directed": True,
      "conditions": "This role explicitly trusts this IAM User."
    },
    {
      "id": "edge:tag-lambda-mbv:ASSUME_ROLE:lambda-role-mbv",
      "src": "288528695623:us-east-1:lambda:tag-lambda-mbv",
      "dst": "288528695623:iam_role:lambda-role-mbv",
      "relation": "ASSUME_ROLE",
      "directed": True,
      "conditions": "A role that a Lambda function can assume."
    },
    {
      "id": "edge:lambda-role-mbv:ELEVATES_PRIVILEGE:admin_mbv",
      "src": "288528695623:iam_role:lambda-role-mbv",
      "dst": "288528695623:iam_user:admin_mbv",
      "relation": "ELEVATES_PRIVILEGE",
      "directed": True,
      "conditions": "This role can elevate privileges of user admin_mbv via iam:AttachUserPolicy."
    },
    {
      "id": "edge:lambda-role-mbv:ELEVATES_PRIVILEGE:even",
      "src": "288528695623:iam_role:lambda-role-mbv",
      "dst": "288528695623:iam_user:even",
      "relation": "ELEVATES_PRIVILEGE",
      "directed": True,
      "conditions": "This role can elevate privileges of user even via iam:AttachUserPolicy."
    }
  ]
}


def get_embedding(text):
    """Bedrock Cohere embed-v4로 텍스트를 벡터로 변환 (search_query 타입)"""
    native_request = {
        "texts": [text],
        "input_type": "search_query",
        "truncate": "NONE"
    }
    response = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(native_request))
    res_body = json.loads(response.get('body').read())
    embeddings = res_body.get('embeddings')
    return embeddings.get('float')[0] if isinstance(embeddings, dict) else embeddings[0]


def main():
    print("=" * 70)
    print("RAG 유사도 검증 테스트")
    print(f"실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # 1. 인프라 JSON을 mbv_search.py와 동일한 방식으로 가공
    # mbv_search.py는 search_pandyo.json의 resources > content를 추출하지만
    # 우리는 직접 인프라 JSON을 제공하므로 전체를 사용
    query_text = json.dumps(TARGET_INFRA, ensure_ascii=False)
    print(f"\n📊 인프라 데이터 길이: {len(query_text)}자")

    # 2. 벡터 임베딩
    print("\n🔄 인프라 데이터 임베딩 중...")
    query_vector = get_embedding(query_text)
    print(f"✅ 임베딩 완료 (벡터 차원: {len(query_vector)})")

    # 3. Qdrant 검색 — 전체 문서에 대해 유사도 순위 확인 (limit=10)
    print("\n🔎 Qdrant 벡터 검색 중...")
    search_response = q_client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=10  # 모든 문서 가져오기
    )

    results = search_response.points

    # 4. 결과 출력
    print("\n" + "=" * 70)
    print("📋 유사도 검색 결과 (전체 순위)")
    print("=" * 70)

    expected_top = {"iam_privesc_by_key_rotation", "eventbridge_target"}
    actual_top2 = set()

    for i, hit in enumerate(results):
        p = hit.payload
        title = p.get('title', 'unknown')
        description = p.get('description', '')
        score = hit.score

        # 순위 마킹
        if i < 2:
            actual_top2.add(title)

        # 기대 결과 마킹
        marker = ""
        if title in expected_top:
            marker = " ⭐ (기대 Top)"

        print(f"  [{i+1}위] {title:40s} | 유사도: {score:.4f}{marker}")
        print(f"         📌 문서 경로: {description}")
        print(f"         {'─' * 50}")

    # 5. 기대값 검증
    print("\n" + "=" * 70)
    print("🧪 검증 결과")
    print("=" * 70)

    print(f"\n  기대 Top-2: {sorted(expected_top)}")
    print(f"  실제 Top-2: {sorted(actual_top2)}")

    if expected_top == actual_top2:
        print("\n  ✅ 성공! iam_privesc_by_key_rotation과 eventbridge_target이 Top-2에 위치합니다.")
    else:
        missing = expected_top - actual_top2
        unexpected = actual_top2 - expected_top
        print(f"\n  ❌ 실패!")
        if missing:
            print(f"     누락된 기대 문서: {missing}")
        if unexpected:
            print(f"     예상 외 Top 문서: {unexpected}")

    # 6. Top-2 유사도 점수 차이 분석
    if len(results) >= 3:
        gap = results[1].score - results[2].score
        print(f"\n  📊 Top-2 ↔ 3위 유사도 차이: {gap:.4f}")
        if gap > 0.05:
            print("     ✅ Top-2가 3위 대비 충분히 분리됨")
        else:
            print("     ⚠️  Top-2와 3위의 차이가 작음 — 추가 분석 필요")

    if len(results) >= 2:
        gap_12 = results[0].score - results[1].score
        print(f"  📊 1위 ↔ 2위 유사도 차이: {gap_12:.4f}")

    print(f"\n{'=' * 70}")
    print("테스트 완료")
    print(f"{'=' * 70}")

    return {
        "success": expected_top == actual_top2,
        "rankings": [
            {"rank": i+1, "title": hit.payload.get('title'), "score": hit.score}
            for i, hit in enumerate(results)
        ]
    }


if __name__ == "__main__":
    main()
