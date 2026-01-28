// aws 서비스 및 정책 데이터 임포트

import awsServices from '../json/cliset/awsServices.json' with {type: 'json'};

let currentStep = 0;
        const totalSteps = 5;
        const stepTitles = ['사용자 설정', 'CLI 생성', '취약점 분석', '실행', '완료'];


        console.log(awsServices);


        const config = {
            region: '',
            infrastructureType: '',
            description: '',
            selectedServices: {},
            customPolicies: [],
            selectedService: null
        };

        window.config = config;

        window.previousStep = previousStep;


        // Initialize
        let hasStateFromURL = false;
        window.onload = function() {

            const params = new URLSearchParams(window.location.search);
            if(params.has("state")){
                try{
                    const decoded = decodeURIComponent(params.get("state"));
                    Object.assign(config, JSON.parse(decoded));
                    currentStep=0
                    hasStateFromURL = true
                }catch(e){
                    console.error("State 파싱 오류:",e);
                }
            }
            // UI 갱신
            renderProgressSteps();
            updateNavigation();
            // loadFormData();
            // populateLoggingData();
            renderServiceCards();
            setupRegionSelector();
            //previousStep();
            if(hasStateFromURL){
                this.setTimeout(()=>{
                    nextStep()
                },0)
            }
        };

               // Region Selector
        function setupRegionSelector() {
            document.getElementById('region').addEventListener('change', function(e) {
                config.region = e.target.value;
                updateNavigation();
            });
        }

        // Render Service Cards
        function renderServiceCards() {
            const container = document.getElementById('servicesGrid');
            container.innerHTML = '';

            awsServices.forEach(service => {
                const card = createServiceCard(service);
                container.appendChild(card);
            });
        }

function createServiceCard(service) {
  const card = document.createElement('div');
  card.className = 'service-card';
  card.id = `service-${service.id}`;

  card.onclick = () => toggleServiceSelect(service.id);

  const icon = document.createElement('div');
  icon.className = 'service-icon';
  icon.textContent = service.icon;

  const info = document.createElement('div');
  info.className = 'service-info';
  info.innerHTML = `
    <div class="service-name">${service.name}</div>
    <div class="service-desc">${service.description}</div>
  `;

  card.appendChild(icon);
  card.appendChild(info);

  return card;
}
function toggleServiceSelect(serviceId) {
  // 기존 선택된 서비스 카드 해제
  if (config.selectedService) {
    const prevCard = document.getElementById(`service-${config.selectedService}`);
    if (prevCard) {
      prevCard.classList.remove('selected');
    }
  }

  // 같은 걸 다시 누르면 선택 해제
  if (config.selectedService === serviceId) {
    config.selectedService = null;
    updateNavigation();
    return;
  }

  // 새 서비스 선택
  config.selectedService = serviceId;

  const card = document.getElementById(`service-${serviceId}`);
  card.classList.add('selected');

  updateNavigation();
}



        // Progress Steps
        function renderProgressSteps() {
            const container = document.getElementById('progressSteps');
            container.innerHTML = '';
            
            for (let i = 0; i < totalSteps; i++) {
                const stepItem = document.createElement('div');
                stepItem.className = 'step-item';
                
                const stepContent = document.createElement('div');
                stepContent.className = 'step-content';
                
                const stepCircle = document.createElement('div');
                stepCircle.className = `step-circle ${i === currentStep ? 'active' : i < currentStep ? 'completed' : 'pending'}`;
                stepCircle.textContent = i + 1;
                
                const stepLabel = document.createElement('p');
                stepLabel.className = `step-label ${i === currentStep ? 'active' : i < currentStep ? 'completed' : 'pending'}`;
                stepLabel.textContent = stepTitles[i];
                
                stepContent.appendChild(stepCircle);
                stepContent.appendChild(stepLabel);
                stepItem.appendChild(stepContent);
                
                if (i < totalSteps - 1) {
                    const stepLine = document.createElement('div');
                    stepLine.className = `step-line ${i < currentStep ? 'completed' : 'pending'}`;
                    stepItem.appendChild(stepLine);
                }
                
                container.appendChild(stepItem);
            }
        }



        // Navigation
        function nextStep() {
            if (currentStep < totalSteps - 1) {
                // 스텝 0 열어 놓기
                // if (currentStep === 0 && !validateStep0()) {
                //     return;
                // }
                // 추가: 취약점 분석(2)에서 실행(3) 단계로 넘어갈 때 grokjson 실행
        // (배열 인덱스: 0사용자설정, 1CLI생성, 2취약점분석, 3실행, 4로깅)
                // step0 ->1로 갈 때 cli 요소 보기
                if(currentStep === 0){
                    if(!hasStateFromURL){
                    if (!config.selectedService){
                        alert("서비스를 선택하세요.");
                        return;
                    } else if (!config.region){
                        alert("리전을 선택하세요.");
                        return;
                    }
                    console.log("선택된 서비스:",config.selectedService);
                    location.href= `/service/${config.selectedService}?region=${config.region}`;
                    return;
                }
            }

                if (currentStep === 2){
                    console.log("Grok Json 생성 시작")
                    grokjson();
                }

                if (currentStep ===1){
                    console.log("사용자 입력 CLI:",config.customCLI);
                    //다음 스텝으로 넘어갈 때 람다 백엔드로 전달
                    lambda_invoke();
                    return; //람다 호출 후 정지
                }
                
                currentStep++;
                updateSteps();
            }
        }

        function previousStep() {
            if (currentStep > 0) {
                currentStep--;
                updateSteps();

                // step-0으로 돌아갈 때 URL 파라미터 제거
                if (currentStep === 0) {
                const cleanUrl = window.location.origin + window.location.pathname;
                window.history.replaceState({}, document.title, cleanUrl);
                }
            }
        }

        function updateSteps() {
            // Hide all steps
            for (let i = 0; i < totalSteps; i++) {
                document.getElementById(`step-${i}`).classList.remove('active');
            }
            
            // Show current step
            document.getElementById(`step-${currentStep}`).classList.add('active');
            
            renderProgressSteps();
            updateNavigation();

            if(currentStep===1){
                loadCLIFromBackend();
            }
        }

        function updateNavigation() {
            const prevBtn = document.getElementById('prevBtn'); 
            const nextBtn = document.getElementById('nextBtn');
            
            prevBtn.disabled = currentStep === 0;

            
            if (currentStep === totalSteps - 1) {
                // nextBtn.innerHTML = '새로 시작하기';
                // nextBtn.className = 'btn btn-success btn-lg';
                // nextBtn.onclick = function() {
                //     currentStep = 0;
                //     resetForm();
                //     updateSteps();
                // };
                nextBtn.style.display = 'none';
            } else {
                nextBtn.innerHTML = `다음 <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>`;
                nextBtn.className = 'btn btn-primary btn-lg';
                nextBtn.onclick = nextStep;
                
                //스텝 0 열어놓기
                // if (currentStep === 0) {
                //     nextBtn.disabled = !validateStep0();
                // }else 
                if(currentStep ===1){ 
                    //cli 입력 없을 시 다음 버튼 비활성화
                    nextBtn.disabled = !config.customCLI;
                } 
                else {
                    //위 조건을 제외한 나머지 스텝에서 상시 다음 버튼 활성화
                    nextBtn.disabled = false;
                }
            }
        }

        // // Form Validation
        // function validateStep0() {
        //     const region = document.getElementById('region').value;
        //     const infrastructureType = document.getElementById('infrastructureType').value;
        //     const description = document.getElementById('description').value;
        //     const iamCredentials = document.getElementById('iamCredentials').value;
            
        //     return region && infrastructureType && description && iamCredentials;
        // }


        // function resetForm() {
        //     document.getElementById('region').value = '';
        //     document.getElementById('infrastructureType').value = '';
        //     document.getElementById('description').value = '';
        //     document.getElementById('iamCredentials').value = '';
            
        //     config.region = '';
        //     config.infrastructureType = '';
        //     config.description = '';
        //     config.iamCredentials = '';
            
        //     // Reset CLI generation
        //     document.getElementById('generateContainer').style.display = 'flex';
        //     document.getElementById('generatedContent').classList.remove('show');
            
        //     // Reset analysis
        //     document.getElementById('analysisIdle').style.display = 'block';
        //     document.getElementById('analysisProgress').classList.add('hidden');
        //     document.getElementById('analysisResults').classList.add('hidden');
        //     document.getElementById('analysisProgressBar').style.width = '0%';
            
        //     // Reset execution
        //     document.getElementById('executionIdle').style.display = 'block';
        //     document.getElementById('executionSteps').classList.add('hidden');
        // }

        // CLI Generation



        // step-1로딩 시 cli가져오기
        async function loadCLIFromBackend(){
            if(currentStep !==1) return;
            
            //url에서 state
            const params = new URLSearchParams(window.location.search);
            if(!params.has("state")){
                console.log("url에 state없음")
                alert("URL에 인프라 정보가 없습니다.")
                return;
            }
            const stateFromURL = decodeURIComponent(params.get("state"));
            const textarea = document.getElementById("inputCLI");
    if (textarea) {
        textarea.value = "CLI를 생성 중입니다... 잠시만 기다려 주세요.";
        textarea.disabled = true; // 생성 중 수정 방지
    }
            try {
            const response = await fetch("/cli_create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ state: config }) // <-- stringify
            });

            if (!response.ok){
                throw new Error('서버 응답 실패')
            }


            const data = await response.json(); // JSON으로 변환
            console.log("전체",data)
            console.log("받은 CLI:", data.cli);


            // textarea에 CLI 넣기
            if (textarea){ 
                textarea.value = data.cli;  
                textarea.disabled = false;
        }
            } catch (err) {
            console.error("CLI 로드 실패:", err);
                if(textarea){
                    textarea.value="CLI 생성에 실패했습니다.";
                    textarea.disabled= false
                }
            }
        }



        //사용자 입력 CLI 전역 저장
function saveCLI() {
    const cliInput = document.getElementById('inputCLI').value.trim();
    const nextBtn = document.getElementById('nextBtn');
    const saveBtn = document.getElementById('saveCliBtn');

    if (cliInput) {
        //grok에서는 user_cli_input 변수로 사용
        config.customCLI = cliInput;
        saveBtn.innerText = "저장 완료 ✓";
        saveBtn.style.backgroundColor = "#16a34a"; // 초록색 피드백
        nextBtn.disabled = false; // 이제 다음으로 갈 수 있음
    } else {
        alert("내용을 입력해주세요.");
    }
}

// 2. 초기화(재생성): 입력창과 전역 변수를 모두 비우고 다음 버튼 잠금
function resetCLI() {
    if (confirm("입력한 내용을 모두 지우시겠습니까?")) {
        const nextBtn = document.getElementById('nextBtn');
        const saveBtn = document.getElementById('saveCliBtn');
        const inputArea = document.getElementById('inputCLI');

        // 값 초기화
        config.customCLI = "";
        inputArea.value = "";
        
        // UI 복구
        saveBtn.innerText = "명령어 저장";
        saveBtn.style.backgroundColor = ""; 
        nextBtn.disabled = true; // 다시 잠금
    }
}

// cli 생성 -> 취약점 분석으로 넘어갈 때 람다 호출하기 ... 를 위해서 백엔드에 cli 넘겨주기
async function lambda_invoke() {
    const nextBtn = document.getElementById('nextBtn');
    
    // 1. 시각적 피드백 (중복 클릭 방지)
    nextBtn.disabled = true;
    const originalText = nextBtn.innerHTML;
    nextBtn.innerHTML = "통신 중...";

    try {
        console.log("람다 호출 시작...");
        const response = await fetch('/lambda_invoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ "customCLI": config.customCLI })
        });

        if (!response.ok) throw new Error('서버 응답 실패');

        const data = await response.json();
        console.log("람다 호출 완료:", data);

        // 2. ★ 값이 정상적으로 왔을 때만 다음 스텝으로 이동 ★
        currentStep++; 
        updateSteps();
        
        // // Step 2로 넘어왔으니 바로 분석 시작
        // startAnalysis();

    } catch (error) {
        console.error("에러:", error);
        alert("람다 호출 중 오류가 발생했습니다. 다시 시도해주세요.");
    } finally {
        // 3. 버튼 상태 복구
        nextBtn.disabled = false;
        nextBtn.innerHTML = originalText;
    }
}



// Vulnerability Analysis
        function startAnalysis() {
            document.getElementById('analysisIdle').style.display = 'none';
            document.getElementById('analysisProgress').classList.remove('hidden');
            document.getElementById('analysisResults').classList.add('hidden');
            
            let progress = 0;
            const interval = setInterval(() => {
                progress += 10;
                document.getElementById('analysisProgressBar').style.width = progress + '%';
                document.getElementById('progressText').textContent = progress + '% 완료';
                
                if (progress >= 100) {
                    clearInterval(interval);
                    // setTimeout(() => {
                    //     showAnalysisResults();
                    // }, 500);
                }
            }, 300);

            
                    ////////
        //     // API 호출
             fetch('/mbv_search', {
                 method: 'POST',
                 headers: {
                     'Content-Type': 'application/json'
                 },
                 body: JSON.stringify(
                     {
                         step: 'vulnerability_analysis'
                     }
                 )
             })
             .then(res => {
                 if (!res.ok) {
                     throw new Error('MBV API 호출 실패');
             }
                 return res.json();
             })
             .then(data => {
                 console.log('[MBV 분석 결과]', data);
                showAnalysisResults(data);
             })
             .catch(err => {
                 console.error('취약점 분석 API 에러:', err);
             });
             /////////
         }


        // 취약점 분석 결과 표시
        function showAnalysisResults(data) {
            if (!data){
                console.log("분석 결과 데이터 없음");
                return;
            }
            document.getElementById('analysisProgress').classList.add('hidden');
            document.getElementById('analysisResults').classList.remove('hidden');


            // 사용자 인프라 데이터 반영
            document.getElementById('infrastructureJSON').textContent = JSON.stringify(data.infrastructure, null, 2);
            
            
            //취약점 데이터 반영(LLM 분석 결과)
            const analysisResult = data.analysis; // 백엔드 반환 전체
            const vulnerabilities = (analysisResult && analysisResult.vulnerabilities) ? analysisResult.vulnerabilities : [];

            console.log("취약점데이터:",vulnerabilities)

            const container = document.getElementById('vulnerabilityList');

            container.innerHTML = '';

            
            if (data.analysis ==1 ){
                console.log("취약점 데이터 없음")
container.innerHTML = `
            <div style="text-align:center; padding:40px; background:#f9fafb; border-radius:8px; border:1px dashed #d1d5db;">
                <p style="font-size: 18px; color: #374151; font-weight: 600;">탐지된 취약점이 없습니다.</p>
                <p style="font-size: 14px; color: #6480b8; margin-top: 8px;">분석 결과, 현재 인프라 구조에서 일치하는 취약점 패턴이 발견되지 않았습니다.</p>
            </div>`;
        return;
            }
            if (vulnerabilities.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:20px;">발견된 취약점이 없거나 분석 중 오류가 발생했습니다.</p>';
        return;
    }
            
            vulnerabilities.forEach((vuln, index) => {
                const card = document.createElement('div');
                card.className = `vulnerability-card ${vuln.severity}`;
                
                const badgeClass = vuln.severity === 'high' ? 'badge-danger' : vuln.severity === 'medium' ? 'badge-warning' : 'badge-secondary';
                
                let attackPathHTML = '<div class="attack-path">';
                vuln.attackPath.forEach((step, i) => {
                    attackPathHTML += `<span class="attack-path-item">${step}</span>`;
                    if (i < vuln.attackPath.length - 1) {
                        attackPathHTML += '<span class="attack-path-arrow">→</span>';
                    }
                });
                attackPathHTML += '</div>';
                
                card.innerHTML = `
                    <div style="display: flex; align-items: start; justify-content: space-between; margin-bottom: 12px;">
                        <div>
                            <h3 style="font-weight: 600; margin-bottom: 4px;">${index + 1}. ${vuln.title}</h3>
                            <div style="display: flex; gap: 8px; margin-top: 8px;">
                                <span class="badge ${badgeClass}">${vuln.severity.toUpperCase()}</span>
                                <span class="badge badge-secondary">CVSS: ${vuln.cvss_score}</span>
                            </div>
                        </div>
                    </div>
                    <div style="padding: 12px; background: white; border-radius: 6px; margin-bottom: 12px;">
                        <p style="font-weight: 500; font-size: 13px; color: #232F3E; margin-bottom: 4px;">취약점 설명</p>
                        <p style="color: #374151; font-size: 14px;">${vuln.description}</p>
                    </div>
                    <div style="padding: 12px; background: white; border-radius: 6px; margin-bottom: 12px;">
                        <p style="font-weight: 500; font-size: 13px; color: #232F3E; margin-bottom: 8px;">공격 경로 (Attack Path)</p>
                        ${attackPathHTML}
                    </div>
                    <div style="padding: 12px; background: white; border-radius: 6px; margin-bottom: 12px;">
                        <p style="font-weight: 500; font-size: 13px; color: #232F3E; margin-bottom: 4px;">잠재적 영향</p>
                        <p style="color: #6B7280; font-size: 13px;">${vuln.impact}</p>
                    </div>
                    <div class="recommendation-box">
                        <p class="recommendation-title">✓ 권장 사항</p>
                        <p class="recommendation-text">${vuln.recommendation}</p>
                    </div>
                `;
                
                container.appendChild(card);
            });
        }

        // Execution
//해당 페이지를 읽을 때 json 생성 및 띄우기
async function grokjson() {
    console.log("그록 JSON 생성 시작");
    
    // UI 요소들 가져오기
    const policyPreviewContainer = document.getElementById('policyPreviewContainer');
    const policyPreviewJson = document.getElementById('policyPreviewJson');
    const policyLoading = document.getElementById('policyLoading');
    const readyToExecute = document.getElementById('readyToExecute');

    try {
        const response = await fetch('/grok_json', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                "customCLI": config.customCLI
            })
        });
        const data = await response.json();

        if (data.message === "success") {
            console.log("그록 JSON생성 완료");

            // 1. 전역 변수에 저장 (나중에 executeProcess에서 사용)
            latestGrokPolicyJSON = data.grok_result;
            user_cli_input = data.user_cli_input;

            // 2. Grok 응답 내에서 순수 JSON 정책 부분만 추출하기
            // 로그를 보면 data.grok_result.choices[0].message.content에 JSON이 들어있습니다.
            const rawContent = data.grok_result.choices[0].message.content;
            
            // 3. 화면에 JSON 뿌려주기
            policyPreviewJson.textContent = rawContent; // 텍스트로 삽입

            // 4. UI 상태 변경 (로딩 숨기고 결과 보여주기)
            policyLoading.style.display = 'none';           // 로딩 스피너 숨김
            policyPreviewContainer.style.display = 'block'; // JSON 박스 표시
            readyToExecute.style.display = 'block';         // 실행하기 버튼 표시

        } else {
            alert("정책 생성에 실패했습니다: " + data.error);
        }

    } catch (error) {
        console.error("JSON 생성 에러:", error);
        policyLoading.innerHTML = `<p style="color:red;">에러가 발생했습니다. 로그를 확인하세요.</p>`;
    }
}

async function executeProcess() {
    // 1. 초기 UI 설정
    document.getElementById('executionIdle').style.display = 'none';
    const executionSteps = document.getElementById('executionSteps');
    const executionComplete = document.getElementById('executionComplete');
    executionSteps.classList.remove('hidden');
    executionComplete.classList.add('hidden');

    const steps = [
        { name: 'Grok 엔진 분석 중...', id: 'step-0' },
        { name: 'IAM 정책 생성 중...', id: 'step-1' },
        { name: 'AWS Lambda 검증 중...', id: 'step-2' },
        { name: '결과 정리 중...', id: 'step-3' }
    ];

    const container = document.getElementById('stepsContainer');
    container.innerHTML = '';

    // UI 미리 생성
    steps.forEach((step, index) => {
        const stepDiv = document.createElement('div');
        stepDiv.className = 'execution-step';
        stepDiv.innerHTML = `
            <div class="step-icon pending" id="icon-${index}"></div>
            <div style="flex: 1;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <p style="font-weight: 500;">${step.name}</p>
                    <span style="font-size: 13px; color: #6B7280;" id="time-${index}"></span>
                </div>
                <p style="font-size: 13px; color: #16a34a; margin-top: 4px; display: none;" id="status-${index}">완료됨</p>
            </div>
        `;
        container.appendChild(stepDiv);
    });

    // 2. 백엔드 API 호출 시작
    const apiPromise = fetch('/grok_exe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            "grok_result": latestGrokPolicyJSON,
            "user_cli_input": user_cli_input
        })
    }).then(res => res.json());

    // 3. UI 애니메이션 진행 및 API 동기화
    try {
        for (let i = 0; i < steps.length; i++) {
            // 마지막 단계 전까지는 시각적인 가짜 딜레이를 줍니다 (사용자 경험용)
            if (i < steps.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 1400)); // 단계별 최소 노출 시간
            } else {
                // 마지막 단계("결과 정리 중")에서는 실제 API 응답이 올 때까지 기다립니다.
                const result = await apiPromise;
                
                if (result.message !== "success") {
                    throw new Error(result.error || "Unknown Error");
                }
                
                console.log("백엔드 응답 완료:", result);
            }

            // 해당 단계 완료 표시 UI 업데이트
            completeStepUI(i);
        }

        // 4. 모든 단계 완료 후 성공 화면 노출
        executionComplete.classList.remove('hidden');

    } catch (error) {
        console.error("실행 에러:", error);
        alert("오류가 발생했습니다: " + error.message);
    }
}

// UI 업데이트를 위한 헬퍼 함수
function completeStepUI(index) {
    const icon = document.getElementById(`icon-${index}`);
    icon.className = 'step-icon';
    icon.innerHTML = '<svg width="20" height="20" fill="#16a34a" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>';
    
    const now = new Date().toLocaleTimeString('ko-KR');
    document.getElementById(`time-${index}`).textContent = now;
    document.getElementById(`status-${index}`).style.display = 'block';
}

        // Logging Tabs
        function switchTab(tabName) {
            // Remove active from all tabs
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Add active to selected tab
            event.target.classList.add('active');
            document.getElementById(`tab-${tabName}`).classList.add('active');
        }

        //로그 분석
        // function populateLoggingData() {
        //     // AI Logs
        //     const aiLogs = [
        //         { timestamp: '2026-01-14 14:32:15', action: 'IAM_CREDENTIAL_CREATE', user: 'AI-System', resource: 'arn:aws:iam::123456789012:user/ai-temp-user-7d8f9', status: 'SUCCESS', details: 'AI가 임시 IAM 사용자 생성' },
        //         { timestamp: '2026-01-14 14:32:18', action: 'IAM_POLICY_ATTACH', user: 'AI-System', resource: 'AutoGenerated-ec2-Policy', status: 'SUCCESS', details: 'AI 생성 정책 연결' },
        //         { timestamp: '2026-01-14 14:32:22', action: 'EC2_INSTANCE_CREATE', user: 'ai-temp-user-7d8f9', resource: 'i-0a1b2c3d4e5f6g7h8', status: 'SUCCESS', details: 'EC2 인스턴스 생성 완료' },
        //         { timestamp: '2026-01-14 14:32:35', action: 'IAM_CREDENTIAL_DELETE', user: 'AI-System', resource: 'arn:aws:iam::123456789012:user/ai-temp-user-7d8f9', status: 'SUCCESS', details: '임시 자격 증명 삭제 완료' }
        //     ];
            
        //     const aiLogsContainer = document.getElementById('aiLogsContent');
        //     aiLogsContainer.innerHTML = '';
            
        //     aiLogs.forEach(log => {
        //         const entry = document.createElement('div');
        //         entry.className = 'log-entry';
        //         entry.innerHTML = `
        //             <div class="log-header">
        //                 <div style="display: flex; gap: 8px;">
        //                     <span class="badge badge-secondary">${log.action}</span>
        //                     <span class="badge badge-success">성공</span>
        //                 </div>
        //                 <span class="log-time">${log.timestamp}</span>
        //             </div>
        //             <div class="log-details">
        //                 <p><span style="color: #6B7280;">사용자:</span> <span style="font-family: monospace;">${log.user}</span></p>
        //                 <p><span style="color: #6B7280;">리소스:</span> <span style="font-family: monospace; font-size: 12px;">${log.resource}</span></p>
        //                 <p style="color: #374151;">${log.details}</p>
        //             </div>
        //         `;
        //         aiLogsContainer.appendChild(entry);
        //     });
            
        //     // CloudTrail Logs
        //     const cloudTrailLogs = [
        //         { timestamp: '2026-01-14 14:32:15', eventName: 'CreateUser', eventSource: 'iam.amazonaws.com', userIdentity: 'AI-System', sourceIP: '192.0.2.1', userAgent: 'AWS-Internal', status: '✓ 검증됨' },
        //         { timestamp: '2026-01-14 14:32:18', eventName: 'AttachUserPolicy', eventSource: 'iam.amazonaws.com', userIdentity: 'AI-System', sourceIP: '192.0.2.1', userAgent: 'AWS-Internal', status: '✓ 검증됨' },
        //         { timestamp: '2026-01-14 14:32:22', eventName: 'RunInstances', eventSource: 'ec2.amazonaws.com', userIdentity: 'ai-temp-user-7d8f9', sourceIP: '192.0.2.1', userAgent: 'aws-cli/2.0', status: '✓ 검증됨' },
        //         { timestamp: '2026-01-14 14:32:35', eventName: 'DeleteUser', eventSource: 'iam.amazonaws.com', userIdentity: 'AI-System', sourceIP: '192.0.2.1', userAgent: 'AWS-Internal', status: '✓ 검증됨' }
        //     ];
            
        //     const cloudTrailContainer = document.getElementById('cloudtrailContent');
        //     cloudTrailContainer.innerHTML = '';
            
        //     cloudTrailLogs.forEach(log => {
        //         const entry = document.createElement('div');
        //         entry.className = 'log-entry';
        //         entry.innerHTML = `
        //             <div class="log-header">
        //                 <div style="display: flex; gap: 8px;">
        //                     <span class="badge badge-secondary">${log.eventName}</span>
        //                     <span class="badge badge-success">${log.status}</span>
        //                 </div>
        //                 <span class="log-time">${log.timestamp}</span>
        //             </div>
        //             <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px;">
        //                 <p><span style="color: #6B7280;">소스:</span> <span style="font-family: monospace; font-size: 12px;">${log.eventSource}</span></p>
        //                 <p><span style="color: #6B7280;">사용자:</span> <span style="font-family: monospace; font-size: 12px;">${log.userIdentity}</span></p>
        //                 <p><span style="color: #6B7280;">IP:</span> <span style="font-family: monospace;">${log.sourceIP}</span></p>
        //                 <p><span style="color: #6B7280;">Agent:</span> <span style="font-family: monospace; font-size: 12px;">${log.userAgent}</span></p>
        //             </div>
        //         `;
        //         cloudTrailContainer.appendChild(entry);
        //     });
            
        //     // Alerts
        //     const alerts = [
        //         { type: 'info', message: '모든 AI 생성 활동이 정상적으로 로깅되었습니다', timestamp: '2026-01-14 14:32:40' },
        //         { type: 'success', message: 'CloudTrail 로그와 AI 로그가 일치합니다', timestamp: '2026-01-14 14:32:40' },
        //         { type: 'info', message: '임시 자격 증명이 허용된 CLI 명령만 실행했습니다', timestamp: '2026-01-14 14:32:40' }
        //     ];
            
        //     const alertsContainer = document.getElementById('alertsContent');
        //     alertsContainer.innerHTML = '';
            
        //     alerts.forEach(alert => {
        //         const alertDiv = document.createElement('div');
        //         alertDiv.style.cssText = 'display: flex; align-items: start; gap: 12px; padding: 12px; background: #F9FAFB; border-radius: 6px; border: 1px solid #E5E7EB; margin-bottom: 12px;';
                
        //         let icon = '';
        //         if (alert.type === 'success') {
        //             icon = '<svg width="16" height="16" fill="#16a34a" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>';
        //         } else {
        //             icon = '<svg width="16" height="16" fill="#2563EB" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>';
        //         }
                
        //         alertDiv.innerHTML = `
        //             ${icon}
        //             <div style="flex: 1;">
        //                 <p style="font-size: 14px; font-weight: 500; margin-bottom: 4px;">${alert.message}</p>
        //                 <p style="font-size: 12px; color: #6B7280;">${alert.timestamp}</p>
        //             </div>
        //         `;
        //         alertsContainer.appendChild(alertDiv);
        //     });
        // }