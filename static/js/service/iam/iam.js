
  // const mockResources = { user: ["admin", "dev-user", "hyeok"], role: ["EC2Role", "LambdaRole"], group: ["Admins", "Developers"] };

  // 기본 더미 리소스 데이터 설정. -> 후에 json파일로 별도 관리
let mockResources = { user: [], role: [], group: [] };
  const iamServices = {
    s3: { label: "Amazon S3", actions: ["GetObject", "PutObject", "ListBucket"] },
    ec2: { label: "Amazon EC2", actions: ["StartInstances", "StopInstances", "DescribeInstances"] },
    sts: { label: "AWS STS", actions: ["AssumeRole", "GetAccessKeyInfo"] },
    iam: {label: "AWS IAM", actions: ["List*", "Get*", "Create*"]}
  };
    const state = { 
    resource: "user", 
    selectedEntity: null, 
    service: null, 
    activePolicies: {} // { s3: ["GetObject"], ec2: ["StartInstances"] } 형식
    };
  let isEditingJson = false;


  async function fetchIamResources() {
  try {
    // IAM정보 불러오기
    const response = await fetch('/iam_list',{
      method: 'post',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    if (!response.ok) throw new Error('Network response was not ok');
    
    const data = await response.json();
    
    // 서버 응답 형식이 { user: [...], role: [...], group: [...] }
    mockResources = data;
    
    // 데이터를 다 받아온 후 리스트 렌더링
    renderResourceList();
    console.log("Resources loaded from /iam_list:", mockResources);
  } catch (error) {
    console.error("Failed to fetch IAM resources:", error);
    alert("리소스를 불러오는 데 실패했습니다.");
  }
}


  // URL에서 region 파라미터 읽기
function getUrlParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name) || "";
}

// 초기화 시 state에 region 반영
state.region = getUrlParam("region");
console.log("Region from URL:", state.region);

  function selectResource(type, el) {
    document.querySelectorAll(".sidebar div").forEach(d => d.classList.remove("active"));
    el.classList.add("active");
    state.resource = type;
    document.getElementById("resourceTitle").innerText = type.charAt(0).toUpperCase() + type.slice(1) + "s";
    renderResourceList();
  }

  // 리스트 렌더링
function renderResourceList() {
    const tbody = document.getElementById("resourceList");
    tbody.innerHTML = "";
    
    // mockResources[state.resource]는 이제 객체 배열입니다. [{name: '...', policies: []}, ...]
    mockResources[state.resource].forEach(item => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${item.name}</td>`;
        tr.onclick = () => {
            document.querySelectorAll("#resourceList tr").forEach(r => r.classList.remove("selected"));
            tr.classList.add("selected");
            // 이름과 해당 아이템의 정책 리스트를 같이 넘깁니다.
            selectEntity(item.name, item.policies);
        };
        tbody.appendChild(tr);
    });
}

function selectEntity(name, policies) {
    state.selectedEntity = name;
    document.getElementById("policySection").style.display = "block";
    
    // 기존 AdministratorAccess 하드코딩 대신 실제 정책 리스트를 렌더링
    const policyListEl = document.getElementById("policyList");
    if (policies && policies.length > 0) {
        policyListEl.innerHTML = policies.map(p => `<span class="policy-tag">${p}</span>`).join("");
    } else {
        policyListEl.innerHTML = `<span style="color: #666; font-size: 12px;">No attached policies</span>`;
    }
}

  
  // 서비스 옵션 렌더링 (기존 동일)
  function renderServiceOptions() {
    const select = document.getElementById("serviceSelect");
    Object.entries(iamServices).forEach(([key, svc]) => {
      const opt = document.createElement("option");
      opt.value = key;
      opt.textContent = svc.label;
      select.appendChild(opt);
    });
  }

  // 액션 선택 영역 UI 개선
function selectService(serviceKey) {
state.service = serviceKey;
  const area = document.getElementById("actionArea");
  area.innerHTML = "";
  if (!iamServices[serviceKey]) return;

  // 최신화된 state.activePolicies에서 현재 서비스의 액션들을 가져옴
  const savedActions = state.activePolicies[serviceKey] || [];

  iamServices[serviceKey].actions.forEach(action => {
    // Wildcard(예: List*) 처리나 정확한 매칭 확인
    const isChecked = savedActions.includes(action);
    const label = document.createElement("label");
    label.style.display = "block"; // UI 가독성을 위해 추가
    label.innerHTML = `
      <input type="checkbox" ${isChecked ? "checked" : ""} 
             onchange="toggleAction('${serviceKey}', '${action}', this.checked)"> 
      ${action}`;
    area.appendChild(label);
  });
}

  /* ... 나머지 updatePolicyJson, syncFromJson, goNext 등 로직은 기존 코드와 동일 ... */
  // (지면상 생략하지만 기존 코드를 그대로 붙여넣으시면 됩니다)
  
  function openInlinePolicy() { document.getElementById("inlineBuilder").style.display = "block"; updatePolicyJson(); }


function toggleAction(serviceKey, action, checked) {
  if (!state.activePolicies[serviceKey]) {
    state.activePolicies[serviceKey] = [];
  }

  if (checked) {
    if (!state.activePolicies[serviceKey].includes(action)) {
      state.activePolicies[serviceKey].push(action);
    }
  } else {
    state.activePolicies[serviceKey] = state.activePolicies[serviceKey].filter(a => a !== action);
    // 만약 해당 서비스의 액션이 하나도 없으면 키 삭제
    if (state.activePolicies[serviceKey].length === 0) {
      delete state.activePolicies[serviceKey];
    }
  }
  updatePolicyJson();
}



function updatePolicyJson() {
// 사용자가 직접 편집 중일 때는 덮어씌우지 않음 (커서 튐 방지)
  if (isEditingJson) return; 

  const statements = Object.entries(state.activePolicies)
    .filter(([_, actions]) => actions.length > 0) // 액션이 없으면 제외
    .map(([service, actions]) => {
      return {
        Effect: "Allow",
        Action: actions.map(a => `${service}:${a}`),
        Resource: "*"
      };
    });

  if (statements.length === 0) {
    document.getElementById("policyJson").value = "";
    return;
  }

  const policy = {
    Version: "2012-10-17",
    Statement: statements
  };

  document.getElementById("policyJson").value = JSON.stringify(policy, null, 2);
}


// 1. 사용자 생성 창 열기
window.createNewUser = function() {
    console.log("createNewUser function called"); // 동작 확인용

    // 다른 섹션들 숨기기
    const policySection = document.getElementById("policySection");
    const inlineBuilder = document.getElementById("inlineBuilder");
    if(policySection) policySection.style.display = "none";
    if(inlineBuilder) inlineBuilder.style.display = "none";
    
    // 생성 섹션 보이기
    const createSection = document.getElementById("createUserSection");
    if(createSection) {
        createSection.style.display = "block";
        renderPolicySelector();
    } else {
        console.error("ID 'createUserSection'을 찾을 수 없습니다.");
    }
};

// 2. 취소/닫기
window.hideCreateUser = function() {
    const createSection = document.getElementById("createUserSection");
    if(createSection) createSection.style.display = "none";
    document.getElementById("newUserName").value = "";
};

// 3. 선택 가능한 정책(권한) 목록 렌더링
function renderPolicySelector() {
    const container = document.getElementById("policySelectorList");
    container.innerHTML = "";

    // iamServices에 정의된 서비스들을 선택 가능한 정책으로 표시
    Object.entries(iamServices).forEach(([key, svc]) => {
        const div = document.createElement("div");
        div.style.padding = "10px";
        div.style.borderBottom = "1px solid #eee";
        div.innerHTML = `
            <label style="display: flex; align-items: center; cursor: pointer;">
                <input type="checkbox" class="policy-create-chk" value="${key}FullAccess" style="margin-right: 10px;">
                <div>
                    <strong>${svc.label}FullAccess</strong><br>
                    <small style="color: #666;">${svc.actions.join(", ")} 권한을 포함합니다.</small>
                </div>
            </label>
        `;
        container.appendChild(div);
    });
}

// 4. 생성 완료 버튼 클릭 시
window.submitCreateUser = async function() {
const name = document.getElementById("newUserName").value;
    const selectedCheckboxes = document.querySelectorAll(".policy-create-chk:checked");
    const selectedPolicies = Array.from(selectedCheckboxes).map(cb => cb.value);

    if (!name) {
        alert("사용자 이름을 입력해주세요.");
        return;
    }

    const newUser = {
        name: name,
        policies: selectedPolicies
    };

    try {
        // 서버에 사용자 생성 요청 (예시 경로: /create_user)
        const response = await fetch('/create_user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newUser)
        });

        if (response.ok) {
            alert(`${name} 사용자가 생성되었습니다.`);
            hideCreateUser();
            await fetchIamResources(); // 목록 새로고침
        } else {
            throw new Error("생성 실패");
        }
    } catch (error) {
        console.error("Error creating user:", error);
        // 서버가 아직 준비 안 됐다면 로컬 mock에 강제 추가해서 테스트 가능
        mockResources.user.push(newUser);
        renderResourceList();
        hideCreateUser();
        alert("서버 연결 실패로 로컬 목록에 임시 추가되었습니다.");
    }
}

  function handleJsonKeydown(e) {
  if (e.key === "Tab") {
    e.preventDefault();

    const textarea = e.target;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;

    const tab = "  "; // ← 스페이스 2칸 (원하면 4칸)

    textarea.value =
      textarea.value.substring(0, start) +
      tab +
      textarea.value.substring(end);

    // 커서 위치 유지
    textarea.selectionStart = textarea.selectionEnd = start + tab.length;
  }
}

  // cli 구성을 json포맷에 담아 루트 경로로 전달.
  function goNext() {
    alert("다음 단계로 진행합니다."); 
    console.log(state); 

    location.href = `/?state=${encodeURIComponent(JSON.stringify(state))}`;

}

function syncFromJson() {
try {
    const jsonValue = document.getElementById("policyJson").value;
    
    // 1. 내용이 없으면 전체 초기화
    if(!jsonValue.trim()){
      state.activePolicies = {};
      selectService(state.service); // 현재 체크박스 UI 갱신
      return;
    }

    const json = JSON.parse(jsonValue);
    const newActivePolicies = {};

    // 2. JSON을 읽어서 state 구성
    if (json.Statement && Array.isArray(json.Statement)) {
      json.Statement.forEach(stmt => {
        const actions = Array.isArray(stmt.Action) ? stmt.Action : (stmt.Action ? [stmt.Action] : []);
        
        actions.forEach(fullAction => {
          const [service, action] = fullAction.split(":");
          if (service && action) {
            if (!newActivePolicies[service]) newActivePolicies[service] = [];
            if (!newActivePolicies[service].includes(action)) {
              newActivePolicies[service].push(action);
            }
          }
        });
      });
    }

    // 3. 전역 상태 교체
    state.activePolicies = newActivePolicies;

    // 4. 중요: 현재 보고 있는 서비스의 체크박스 상태 업데이트
    if (state.service) {
      selectService(state.service); 
    }

  } catch (e) {
    // JSON 형식이 깨진 동안(타이핑 중)은 업데이트를 멈춤
  }
}

  // 초기화
// 3. 초기화 부분 수정
async function init() {
  // Region 파라미터 읽기 등 기초 설정
  state.region = getUrlParam("region");
  
  // 서비스 옵션은 정적 데이터이므로 바로 렌더링
  renderServiceOptions();
  
  // 서버에서 리소스 데이터를 가져온 후 리스트 출력
  await fetchIamResources();
}

// 페이지 로드 시 실행
init();