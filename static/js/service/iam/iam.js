  // 스크립트 부분은 기존 로직을 유지하되 UI 업데이트 함수만 약간 수정했습니다.
  
  /* (기존 Mock Data 및 State 동일) */
  const mockResources = { user: ["admin", "dev-user", "hyeok"], role: ["EC2Role", "LambdaRole"], group: ["Admins", "Developers"] };
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

  function renderResourceList() {
    const tbody = document.getElementById("resourceList");
    tbody.innerHTML = "";
    mockResources[state.resource].forEach(name => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${name}</td>`;
      tr.onclick = () => {
        document.querySelectorAll("#resourceList tr").forEach(r => r.classList.remove("selected"));
        tr.classList.add("selected");
        selectEntity(name);
      };
      tbody.appendChild(tr);
    });
  }

  function selectEntity(name) {
    state.selectedEntity = name;
    document.getElementById("policySection").style.display = "block";
    document.getElementById("policyList").innerHTML = `<span class="policy-tag">AdministratorAccess</span>`;
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
  renderResourceList();
  renderServiceOptions();