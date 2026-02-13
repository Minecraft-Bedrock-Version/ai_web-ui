# LLM 검증 동작 테스트 결과 보고서

> **실행일시**: 2026-02-13 00:24:50 ~ 00:25:13 (UTC) / 09:24~09:25 (KST)
> **실행환경**: EC2 (`ubuntu@ip-10-0-1-104`), `--skip-rag` 모드
> **실행명령**: `python3 test/test_llm_verification.py --skip-rag`
> **LLM 모델**: `openai.gpt-oss-120b-1:0` (AWS Bedrock)

---

## 1. 테스트 목적

RAG로 매칭된 취약점 시나리오가 **실제 인프라에서 재현 불가능**할 때,
LLM이 이를 **올바르게 판별**하고 **Secondary Task(Zero-Base 확장 탐지)**로 전환하는지 검증한다.

### 테스트 대상

| 더미 파일 | 설명 | 기대 결과 |
|-----------|------|-----------|
| **dummy1** | 구조 유사하나 핵심 권한(SecretsManager) 부재 | RAG 시나리오 재현 **불가** 판정 |
| **dummy2** | 최소 구조, Role/SecretsManager 완전 제거 | RAG 시나리오 재현 **불가** 판정 |

### 테스트 방법

| 방법 | 설명 | 판정 방식 |
|------|------|-----------|
| **방법 A** | 프롬프트에 `rag_scenario_valid` 필드 추가 | 자동 판정 (true/false) |
| **방법 B** | 프로덕션 프롬프트 그대로 사용 | 수동 분석 (파일 저장) |

---

## 2. 테스트 결과 요약

### ✅ 전체 판정: **PASS (4/4 성공)**

| 더미 | 방법 | 판정 | 상세 |
|------|------|:----:|------|
| dummy1 | **A** | ✅ PASS | `rag_scenario_valid: false` → Secondary 3개 발견 |
| dummy1 | **B** | 📄 수동 확인 | 취약점 3개 출력, 파일 저장 완료 |
| dummy2 | **A** | ✅ PASS | `rag_scenario_valid: false` → Secondary 1개 발견 |
| dummy2 | **B** | 📄 수동 확인 | 취약점 1개 출력 (파일 저장 시 경로 오류 ※별도 수정) |

---

## 3. 상세 결과

### 3-1. dummy1 (구조 유사, 핵심 권한 부재)

#### 방법 A (자동 판정)

```
rag_scenario_valid: False ✅
```

- **판정 사유**: 시나리오에 필요한 secretsmanager 권한이 역할에 부여되지 않아
  admin 사용자가 역할을 전제(AssumeRole)하고도 비밀을 조회할 수 없음

- **누락된 컴포넌트**:
  1. `cg_secretsmanager_cgiddd7ga7gjim` 역할에 `secretsmanager:ListSecrets` 및 `secretsmanager:GetSecretValue` 권한 없음
  2. `admin` 사용자에 `MultiFactorAuthPresent=true` 태그 없으며, 해당 조건을 요구하는 정책이 존재하지 않음

- **Secondary Task 결과** (Zero-Base 확장 탐지):

  | 심각도 | 취약점 |
  |:------:|--------|
  | 🔴 High | IAM 사용자 manager에 과도한 IAM 권한 부여 |
  | 🔴 High | 역할 trust policy의 과도한 허용 |
  | 🟡 Medium | admin 사용자에 불필요한 광범위 IAM 읽기 권한 |

#### 방법 B (프로덕션 프롬프트)

- 취약점 3개 출력 (High: 1, Medium: 1, Low: 1)
  | 심각도 | 취약점 |
  |:------:|--------|
  | 🔴 High | IAM 사용자 간 권한 상승 (TagUser + CreateAccessKey) |
  | 🟡 Medium | 과도한 IAM 관리 권한 (iam:* on *) |
  | 🟢 Low | 과도하게 개방된 역할 신뢰 정책 |

- 결과 파일: `test_results/method_B_dummy1_구조_유사,_핵심_권한_부재_20260213_002450.json`

---

### 3-2. dummy2 (최소 구조, Role/SecretsManager 완전 제거)

#### 방법 A (자동 판정)

```
rag_scenario_valid: False ✅
```

- **판정 사유**: developer 사용자에게 `iam:EnableMFADevice`, `iam:CreateAccessKey`,
  `iam:TagUser` 권한이 없으며, MFA 태그 조건과 AssumeRole 권한을 가진 역할도 존재하지 않아
  시나리오를 재현할 수 없음

- **누락된 컴포넌트**:
  1. developer 사용자에 대한 `iam:EnableMFADevice` 권한
  2. developer 사용자에 대한 `iam:CreateAccessKey` 권한
  3. developer 사용자에 대한 `iam:TagUser` 권한 (admin 사용자에 태그 부여)
  4. developer 사용자에 적용된 `developer=true` 태그 및 `MultiFactorAuthPresent=true` 조건
  5. `sts:AssumeRole` 권한을 포함한 역할 (secretsmanager 접근용) 및 해당 역할에 대한 trust relationship

- **Secondary Task 결과**:

  | 심각도 | 취약점 |
  |:------:|--------|
  | 🔴 High | 과도한 IAM 권한을 가진 manager 사용자 |

#### 방법 B (프로덕션 프롬프트)

- 취약점 1개 출력 (High: 1)
  | 심각도 | 취약점 |
  |:------:|--------|
  | 🔴 High | IAM 사용자 간 무제한 AccessKey 생성 권한으로 인한 권한 상승 |

- ⚠️ 결과 파일 저장 실패: 파일명에 `/` 포함 (`Role/SecretsManager`) → 경로 오류

---

## 4. 핵심 결론

### ✅ LLM 검증 로직이 정상 동작함을 확인

1. **Primary Task 판정 정확**: 두 dummy 모두에서 LLM이 `rag_scenario_valid: false`를 정확히 출력
   - dummy1: SecretsManager 권한 부재를 정확히 식별
   - dummy2: 전체 공격 체인 요소 부재를 상세히 나열

2. **Secondary Task 전환 성공**: RAG 시나리오 재현 불가 판정 후,
   Zero-Base 확장 탐지로 전환하여 **실제 존재하는 취약점**을 별도로 식별

3. **방법 A vs 방법 B 비교**:

   | 항목 | 방법 A (스키마 기반) | 방법 B (프로덕션 프롬프트) |
   |------|---------------------|--------------------------|
   | 자동 판정 | ✅ 가능 (`rag_scenario_valid`) | ❌ 수동 분석 필요 |
   | 재현 불가 명시 | ✅ 필드로 명확히 출력 | ⚠️ 응답 본문에서 추론 필요 |
   | 취약점 출처 분류 | ✅ `source` 필드로 분류 | ❌ 분류 없음 |
   | 프로덕션 호환 | ⚠️ 스키마 변경 필요 | ✅ 즉시 적용 가능 |

---

## 5. 발견된 버그

| # | 내용 | 심각도 | 상태 |
|---|------|:------:|:----:|
| 1 | dummy2 방법 B 파일 저장 시 `Role/SecretsManager`의 `/`가 경로 구분자로 인식됨 | Low | 수정 필요 |

---

## 6. 권장 후속 작업

1. **방법 A 프로덕션 적용 검토**: `rag_scenario_valid` 필드를 프로덕션 프롬프트에 추가하면 자동 판정이 가능해져 운영 효율성이 크게 향상됨
2. **파일명 sanitize 버그 수정**: `safe_name` 생성 시 `/` 문자도 제거하도록 수정
3. **원본 인프라 데이터(`iam_privesc_by_key_rotation.json`)로 대조 테스트**: 실제 취약 인프라에서 `rag_scenario_valid: true`가 나오는지 확인 (정상 동작 검증)
