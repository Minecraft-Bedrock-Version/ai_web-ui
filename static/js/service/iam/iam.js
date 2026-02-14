
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

  // 생성 창 열기 (통합)
  // 전역 변수로 템플릿 저장
let trustTemplates = {};
// 초기화 시 템플릿 가져오기
async function fetchTrustTemplates() {
    trustTemplates = {
        ec2: { label: "EC2", service: "ec2.amazonaws.com" },
        lambda: { label: "Lambda", service: "lambda.amazonaws.com" }
    };
}
// 1. 생성 창 열기 (통합 모달)
function openCreateModal() {
  
    console.log("openCreateModal 호출됨. 현재 타입:", state.resource);

    // 1) 다른 섹션 닫기
    document.getElementById("policySection").style.display = "none";
    document.getElementById("inlineBuilder").style.display = "none";

    // 2) 데이터 초기화 및 보이기
    const type = state.resource;
    const titleMap = { user: "사용자 생성", group: "그룹 생성", role: "역할(Role) 생성" };
    
    document.getElementById("createSectionTitle").innerText = titleMap[type] || "리소스 생성";
    document.getElementById("newResourceName").value = "";
    document.getElementById("createResourceSection").style.display = "block";
    
    // 3) Role 전용 UI 처리
    // const trustField = document.getElementById("trustPolicyField");
    // if (type === "role") {
    //     const trustField = document.getElementById("trustPolicyField");
    //     trustField.innerHTML = `
    //         <label>신뢰할 서비스 선택</label>
    //         <select id="trustServiceSelect" onchange="applyTrustTemplate(this.value)">
    //             ${Object.entries(trustTemplates).map(([key, val]) => 
    //                 `<option value="${key}">${val.label}</option>`
    //             ).join('')}
    //         </select>
    //     `;
    //     trustField.style.display = "block";
        
    //     // 초기값 설정
    //     applyTrustTemplate(Object.keys(trustTemplates)[0]);
    // }
    // else {
    //     trustField.style.display = "none";
    // }

    // 4) 핵심: 관리형 정책 목록 렌더링 함수 실행
    renderPolicySelector(); 
}

// 3. 선택 가능한 정책(권한) 목록 렌더링 함수 (이 함수가 정확히 있는지 확인하세요)
function renderPolicySelector() {
    const container = document.getElementById("policySelectorList");
    if (!container) return;
    
    container.innerHTML = "";

    Object.entries(iamServices).forEach(([key, svc]) => {
        const div = document.createElement("div");
        div.className = "policy-item-row"; // CSS와 연결되는 클래스명 추가
        div.innerHTML = `
            <input type="checkbox" class="policy-create-chk" id="chk-${key}" value="${key}FullAccess">
            <label for="chk-${key}" style="cursor: pointer; flex: 1;">
                <strong>${svc.label}FullAccess</strong>
                <small>${svc.actions.join(", ")} 권한을 포함합니다.</small>
            </label>
        `;
        container.appendChild(div);
    });
}

// 2. 생성 완료 버튼 클릭 시 (통합 제출)
async function submitCreateResource() {
    const type = state.resource; 
    const name = document.getElementById("newResourceName").value;
    
    // 1. 선택된 관리형 정책들 가져오기
    const selectedCheckboxes = document.querySelectorAll(".policy-create-chk:checked");
    const managedPolicies = Array.from(selectedCheckboxes).map(cb => cb.value);
    
    if (!name) return alert("이름을 입력해주세요.");

    // 2. goNext와 동일한 형식의 Payload 구성
    const payload = {
        state: {
            action: "create",       // 리소스 생성을 위한 액션 플래그
            service: "iam",
            resource: type,         // 'user', 'role', 'group'
            name: name,             // 생성할 리소스 이름
            policies: managedPolicies, // 선택한 정책 리스트
            region: state.region
        },
        region: state.region
    };
    console.log("🚀 생성 페이로드 전송:", payload);

    // goNext와 동일한 방식으로 리다이렉트
    const encodedState = encodeURIComponent(JSON.stringify(payload));
    const encodedRegion = encodeURIComponent(state.region);
    
    location.href = `/?state=${encodedState}&region=${encodedRegion}`;
}

// 3. 취소 함수 확인
function hideCreateResource() {
    document.getElementById("createResourceSection").style.display = "none";
}



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
    
    // 1. 정책 렌더링 (기존 로직)
    const policyListEl = document.getElementById("policyList");
    if (policies && policies.length > 0) {
        policyListEl.innerHTML = policies.map(p => `<span class="policy-tag">${p}</span>`).join("");
    } else {
        policyListEl.innerHTML = `<span style="color: #666; font-size: 12px;">No attached policies</span>`;
    }

    // 2. 그룹인 경우 사용자 관리 섹션 노출
    const memberSection = document.getElementById("groupMemberSection");
    if (state.resource === 'group') {
        memberSection.style.display = "block";
        renderGroupMembers(name);
    } else {
        memberSection.style.display = "none";
    }
}

// 현재 그룹의 멤버 표시 (mockResources 구조에 따라 조정 필요)
function renderGroupMembers(groupName) {
    const memberListEl = document.getElementById("memberList");
    // mockResources에서 해당 그룹의 members 데이터를 찾는다고 가정
    const groupData = mockResources.group.find(g => g.name === groupName);
    const members = groupData?.members || []; 

    if (members.length > 0) {
        memberListEl.innerHTML = members.map(m => `<div class="member-item">👤 ${m}</div>`).join("");
    } else {
        memberListEl.innerHTML = `<p style="color:#999; font-size:12px;">멤버가 없습니다.</p>`;
    }
}

// 모달 열기
function openAddUserToGroupModal() {
    const container = document.getElementById("availableUserList");
    container.innerHTML = "";

    // 전체 사용자 목록(mockResources.user)에서 선택 가능하게 표시
    mockResources.user.forEach(user => {
        const div = document.createElement("div");
        div.innerHTML = `
            <label>
                <input type="checkbox" class="user-to-add-chk" value="${user.name}"> ${user.name}
            </label>
        `;
        container.appendChild(div);
    });

    document.getElementById("addUserModal").style.display = "block";
}

function closeAddUserModal() {
    document.getElementById("addUserModal").style.display = "none";
}

// 서버로 데이터 전송
async function submitAddUsersToGroup() {
    const selectedUsers = Array.from(document.querySelectorAll(".user-to-add-chk:checked")).map(cb => cb.value);
    
    if (selectedUsers.length === 0) return alert("추가할 사용자를 선택해주세요.");

    const payload = {
        state: {
            action: "add_user_to_group",
            groupName: state.selectedEntity,
            users: selectedUsers,
            region: state.region
        }
    };

    console.log("🚀 그룹 사용자 추가 페이로드:", payload);
    
    // 기존 goNext와 동일한 방식으로 리다이렉트 (백엔드에서 처리)
    const encodedState = encodeURIComponent(JSON.stringify(payload));
    location.href = `/?state=${encodedState}&region=${encodeURIComponent(state.region)}`;
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

  // 1. 관리형 정책 연결 모달 열기
function openAttachManagedPolicyModal() {
    const container = document.getElementById("managedPolicySelectorList");
    if (!container) return;
    
    container.innerHTML = "";

    // iamServices를 순회하며 체크박스 생성 (이미 연결된 정책은 체크 표시하고 싶다면 logic 추가 가능)
    Object.entries(iamServices).forEach(([key, svc]) => {
        const div = document.createElement("div");
        div.style.padding = "8px";
        div.style.borderBottom = "1px solid #eee";
        
        div.innerHTML = `
            <label style="display: flex; align-items: center; cursor: pointer;">
                <input type="checkbox" class="attach-managed-chk" value="${key}FullAccess" style="margin-right: 10px;">
                <div>
                    <strong style="display:block;">${svc.label}FullAccess</strong>
                    <small style="color: #888;">${svc.actions.join(", ")}</small>
                </div>
            </label>
        `;
        container.appendChild(div);
    });

    document.getElementById("attachPolicyModal").style.display = "block";
}

// 2. 모달 닫기
function closeAttachPolicyModal() {
    document.getElementById("attachPolicyModal").style.display = "none";
}

// 3. 선택된 정책들을 서버로 제출
async function submitAttachManagedPolicies() {
    const selectedCheckboxes = document.querySelectorAll(".attach-managed-chk:checked");
    const selectedPolicies = Array.from(selectedCheckboxes).map(cb => cb.value);
    
    if (selectedPolicies.length === 0) {
        return alert("연결할 정책을 하나 이상 선택해주세요.");
    }

    const payload = {
        state: {
            action: "attach_policy", // 정책 연결 액션 플래그
            service: "iam",
            resource: state.resource,      // 'user', 'role', 'group'
            name: state.selectedEntity,    // 현재 선택된 리소스 이름
            policies: selectedPolicies,    // 선택된 정책 리스트
            region: state.region
        },
        region: state.region
    };

    console.log("🚀 관리형 정책 연결 페이로드 전송:", payload);

    // 공통 리다이렉트 로직
    const encodedState = encodeURIComponent(JSON.stringify(payload));
    const encodedRegion = encodeURIComponent(state.region);
    location.href = `/?state=${encodedState}&region=${encodedRegion}`;
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
    const payload = {
      state: {
        service: "iam",
        resource: state.resource,
        selectedEntity: state.selectedEntity,
        activePolicies: state.activePolicies
      },
      region: state.region
    };

    location.href = `/?state=${encodeURIComponent(JSON.stringify(payload))}&region=${encodeURIComponent(state.region)}`;

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