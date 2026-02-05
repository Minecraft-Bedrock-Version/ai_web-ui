
const title = document.getElementById('page-title');
const formArea = document.getElementById('form-area');

// URL에서 리전 가져오기
const params = new URLSearchParams(window.location.search);
const region = params.get('region')

const mockApi = {
  region: region,

  now_instances: []
};


/* =========================
   옵션 정의
========================= */
const INSTANCE_OPTIONS = {
  os: {
    "amazon-linux": {
      label: "Amazon Linux",
      versions: ["2023", "2"],
      arch: ["x86_64", "arm64"]
    },
    ubuntu: {
      label: "Ubuntu",
      versions: ["20.04", "22.04", "24.04"],
      arch: ["x86_64", "arm64"]
    }
  },
  instanceTypes: {
    x86_64: ["t3.micro", "t3.small"],
    arm64: ["t4g.micro"]
  },
  keypairs: ["없음", "my-key"],
  imds: [
    { value: "optional", label: "IMDSv1 + v2 허용 (취약)" },
    { value: "required", label: "IMDSv2만 허용" }
  ]
};

/* =========================
   단일 상태 모델 (SSOT)
========================= */
const state = {
  instance: {
    name: "my-instance",
    os: "amazon-linux",
    osVersion: "2023",
    arch: "x86_64",
    instanceType: "t3.micro",
    publicIp: "true",
    keypair: "없음",
    imds: "optional",
    encrypted: "true"
  }
};

/* =========================
   템플릿
========================= */
const templates = {
  instance: () => `
    <h3>인스턴스</h3>

        <div class="toolbar">
      <div>
        <button class="btn">인스턴스 시작</button>
        <button class="btn secondary">중지</button>
        <button class="btn secondary">종료</button>
        <button class="btn secondary" data-action="create-instance">새 인스턴스</button>
      </div>
      <button class="btn secondary">새로 고침</button>
      
    </div>
  <table>
    <thead>
      <tr>
        <th>인스턴스 ID</th>
        <th>이름</th>
        <th>상태</th>
        <th>유형</th>
        <th>퍼블릭 IPv4</th>
      </tr>
    </thead>
    <tbody id="instance-table"></tbody>
  </table>
    `,

  instance_create: () => `
      <h3>인스턴스 생성</h3>

      <div class="row"><label>이름</label><input id="i-name"/></div>
      <div class="row"><label>운영체제</label><select id="i-os"></select></div>
      <div class="row"><label>OS 버전</label><select id="i-os-version"></select></div>
      <div class="row"><label>아키텍처</label><select id="i-arch"></select></div>
      <div class="row"><label>인스턴스 타입</label><select id="i-type"></select></div>
      <div class="row"><label>퍼블릭 IP</label><select id="i-public-ip"></select></div>
      <div class="row"><label>키 페어</label><select id="i-keypair"></select></div>
      <div class="row"><label>IMDS 설정</label><select id="i-imds"></select></div>
      <div class="row"><label>루트 볼륨 암호화</label><select id="i-encrypted"></select></div>

      

      <h4>현재 설정 (JSON)</h4>
      <textarea
  id="json-preview"
  spellcheck="false"
></textarea>

      <div class="actions">
        <button class="btn" id="create">생성</button>
        <button class="btn secondary" id="cancel">취소</button>
      </div>

    `,
  keypair: () => `
      <h3>키 페어 생성</h3>
      <div class="row"><label>이름</label><input /></div>
      <div class="cli-preview">aws ec2 create-key-pair --key-name my-key</div>
    `,

  volume: () => `
      <h3>EBS 볼륨 생성</h3>
      <div class="row"><label>크기 (GiB)</label><input type="number" value="8" /></div>
      <div class="row"><label>AZ</label><select><option>ap-northeast-2a</option></select></div>
      <div class="cli-preview">aws ec2 create-volume --size 8</div>
    `,

  ami: () => `
      <h3>AMI 생성</h3>
      <div class="row"><label>소스 인스턴스</label><input /></div>
      <div class="row"><label>AMI 이름</label><input /></div>
      <div class="cli-preview">aws ec2 create-image --instance-id i-xxxx</div>
    `,

  'launch-template': () => `
      <h3>Launch Template 생성</h3>
      <div class="row"><label>이름</label><input /></div>
      <div class="row"><label>AMI</label><input /></div>
      <div class="row"><label>타입</label><input /></div>
      <div class="cli-preview">aws ec2 create-launch-template --launch-template-name lt-demo</div>
    `
};

function select(type, label) {
  title.textContent = label + ' 생성';
  formArea.innerHTML = templates[type]();
  if (type === 'instance') {
    renderInstances();

    // ✅ 여기 추가
    const createBtn = formArea.querySelector('[data-action="create-instance"]');
    if (createBtn) {
      createBtn.addEventListener('click', () => {
        select('instance_create', '인스턴스');
      });
    }
  }

  if (type === 'instance_create') {
    initInstanceForm();
  }
}




function renderTopbar() {
  // document.getElementById("page-title").textContent = "인스턴스";
  document.getElementById("region").textContent =
    `리전: ${region}`;
}

function renderInstances() {
  const tbody = document.getElementById("instance-table");
  tbody.innerHTML = mockApi.now_instances.map(inst => `
    <tr>
      <td>${inst.id}</td>
      <td>${inst.name}</td>
      <td class="status ${inst.state}">
        ${inst.state === "running" ? "실행 중" : "중지됨"}
      </td>
      <td>${inst.type}</td>
      <td>${inst.publicIp}</td>
    </tr>
  `).join("");
}


async function loadInstances() {
  try {
    const res = await fetch("/ec2_list", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ region }) // URL에서 읽은 값을 넘김
    });
    const data = await res.json();

    // 화면 렌더링
    mockApi.now_instances = data.instances;
    mockApi.region = data.region;

    renderTopbar();
    renderInstances();
  } catch (err) {
    console.error("EC2 불러오기 실패", err);
  }
}




/* =========================
   유틸
========================= */
function fillSelect(el, options) {
  el.innerHTML = '';
  options.forEach(opt => {
    if (typeof opt === 'string') {
      el.append(new Option(opt, opt));
    } else {
      el.append(new Option(opt.label, opt.value));
    }
  });
}

function renderJSON() {
  document.getElementById('json-preview').value =
    JSON.stringify(state.instance, null, 2);
}

/* =========================
   초기화
========================= */
function initInstanceForm() {
  const osEl = document.getElementById('i-os');
  const verEl = document.getElementById('i-os-version');
  const archEl = document.getElementById('i-arch');
  const typeEl = document.getElementById('i-type');

  // OS
  Object.entries(INSTANCE_OPTIONS.os).forEach(([k, v]) => {
    osEl.append(new Option(v.label, k));
  });

  fillSelect(verEl, INSTANCE_OPTIONS.os[state.instance.os].versions);
  fillSelect(archEl, INSTANCE_OPTIONS.os[state.instance.os].arch);
  fillSelect(typeEl, INSTANCE_OPTIONS.instanceTypes[state.instance.arch]);

  fillSelect(document.getElementById('i-keypair'), INSTANCE_OPTIONS.keypairs);
  fillSelect(document.getElementById('i-imds'), INSTANCE_OPTIONS.imds);
  fillSelect(document.getElementById('i-public-ip'), [
    { value: "true", label: "할당" },
    { value: "false", label: "할당 안 함" }
  ]);
  fillSelect(document.getElementById('i-encrypted'), [
    { value: "true", label: "활성화" },
    { value: "false", label: "비활성화 (취약)" }
  ]);

  // 초기 값 주입 (1회)
  document.getElementById('i-name').value = state.instance.name;
  osEl.value = state.instance.os;
  verEl.value = state.instance.osVersion;
  archEl.value = state.instance.arch;
  typeEl.value = state.instance.instanceType;
  document.getElementById('i-public-ip').value = state.instance.publicIp;
  document.getElementById('i-keypair').value = state.instance.keypair;
  document.getElementById('i-imds').value = state.instance.imds;
  document.getElementById('i-encrypted').value = state.instance.encrypted;

  /* === UI → State === */
  formArea.querySelectorAll('input, select').forEach(el => {
    el.addEventListener('change', () => {
      const key = el.id.replace('i-', '');
      state.instance[key === 'type' ? 'instanceType' : key] = el.value;

      if (el.id === 'i-os') {
        const osData = INSTANCE_OPTIONS.os[el.value];
        state.instance.osVersion = osData.versions[0];
        state.instance.arch = osData.arch[0];

        fillSelect(verEl, osData.versions);
        fillSelect(archEl, osData.arch);
      }

      if (el.id === 'i-arch') {
        const types = INSTANCE_OPTIONS.instanceTypes[el.value];
        state.instance.instanceType = types[0];
        fillSelect(typeEl, types);
      }

      renderJSON();
    });
  });

  //생성 버튼 + 취소 버튼 가져오기 
  const createBtn = document.getElementById('create');
  const cancelBtn = document.getElementById('cancel');

  createBtn.addEventListener('click', () => {
    // 현재 state.instance + region 합치기
    const payload = {
      state: {
        service: "ec2", // 서비스 식별자 추가
        ...state.instance
      },
      region: mockApi.region  // URL에서 읽은 region
    };

    alert("다음 단계로 이동합니다.")

    // URL에 state 전달
    const url = `/?state=${encodeURIComponent(JSON.stringify(payload))}`;
    console.log("Navigate to:", url);

    // 페이지 이동
    location.href = url;
  });

  cancelBtn.addEventListener('click', () => {
    select('instance', '인스턴스');
    renderInstances();
  });

  renderJSON();
}


// 선택창
document.querySelectorAll('.menu-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.menu-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    select(item.dataset.type, item.textContent);
  });
});
/* =========================
   시작
========================= */
select('instance', '인스턴스');
loadInstances()