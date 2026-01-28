  // 스크립트 부분은 기존 로직을 유지하되 UI 업데이트 함수만 약간 수정했습니다.
  
  /* (기존 Mock Data 및 State 동일) */
  const mockResources = { user: ["admin", "dev-user", "hyeok"], role: ["EC2Role", "LambdaRole"], group: ["Admins", "Developers"] };
  const iamServices = {
    s3: { label: "Amazon S3", actions: ["GetObject", "PutObject", "ListBucket"] },
    ec2: { label: "Amazon EC2", actions: ["StartInstances", "StopInstances", "DescribeInstances"] },
    sts: { label: "AWS STS", actions: ["AssumeRole", "GetAccessKeyInfo"] }
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
function selectService(serviceKey, presetActions = []) {
  state.service = serviceKey;
  const area = document.getElementById("actionArea");
  area.innerHTML = "";
  if (!iamServices[serviceKey]) return;

  // 이전에 이 서비스에 선택했던 액션들이 있다면 가져옴
  const savedActions = state.activePolicies[serviceKey] || [];

  iamServices[serviceKey].actions.forEach(action => {
    const isChecked = savedActions.includes(action);
    const label = document.createElement("label");
    label.innerHTML = `<input type="checkbox" ${isChecked ? "checked" : ""} 
                        onchange="toggleAction('${serviceKey}', '${action}', this.checked)"> ${action}`;
    area.appendChild(label);
  });
  updatePolicyJson();
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
  if (isEditingJson) return;

  const statements = Object.entries(state.activePolicies).map(([service, actions]) => {
    return {
      Effect: "Allow",
      Action: actions.map(a => `${service}:${a}`),
      Resource: "*"
    };
  });

  const policy = {
    Version: "2012-10-17",
    Statement: statements
  };

  // 아무것도 선택 안 된 경우 처리
  if (statements.length === 0) {
    document.getElementById("policyJson").value = "";
    return;
  }

  document.getElementById("policyJson").value = JSON.stringify(policy, null, 2);
}

  // cli 구성을 json포맷에 담아 /경로로 전달.
  function goNext() {
    alert("다음 단계로 진행합니다."); 
    console.log(state); 

    location.href = `/?state=${encodeURIComponent(JSON.stringify(state))}`;

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
    const json = JSON.parse(
      document.getElementById("policyJson").value
    );

    const stmt = json.Statement?.[0];
    if (!stmt || !Array.isArray(stmt.Action)) return;

    const actions = stmt.Action;
    if (actions.length === 0) return;

    const [service] = actions[0].split(":");
    const actionNames = actions.map(a => a.split(":")[1]);

    if (!iamServices[service]) return;

    // 서비스 select 반영
    const select = document.getElementById("serviceSelect");
    select.value = service;

    // UI + state 동기화
    selectService(service, actionNames);

  } catch (e) {
    // JSON 깨졌을 때는 무시
  }
}

  // 초기화
  renderResourceList();
  renderServiceOptions();