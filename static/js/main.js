let currentStep = 0;
        const totalSteps = 5;
        const stepTitles = ['사용자 설정', 'CLI 생성', '취약점 분석', '실행', '로깅'];
        
        const config = {
            region: '',
            infrastructureType: '',
            description: '',
            iamCredentials: ''
        };

        // Initialize
        window.onload = function() {
            renderProgressSteps();
            updateNavigation();
            loadFormData();
            populateLoggingData();
        };

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
                if (currentStep === 0 && !validateStep0()) {
                    return;
                }
                
                currentStep++;
                updateSteps();
            }
        }

        function previousStep() {
            if (currentStep > 0) {
                currentStep--;
                updateSteps();
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
        }

        function updateNavigation() {
            const prevBtn = document.getElementById('prevBtn');
            const nextBtn = document.getElementById('nextBtn');
            
            prevBtn.disabled = currentStep === 0;
            
            if (currentStep === totalSteps - 1) {
                nextBtn.innerHTML = '새로 시작하기';
                nextBtn.className = 'btn btn-success btn-lg';
                nextBtn.onclick = function() {
                    currentStep = 0;
                    resetForm();
                    updateSteps();
                };
            } else {
                nextBtn.innerHTML = `다음 <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>`;
                nextBtn.className = 'btn btn-primary btn-lg';
                nextBtn.onclick = nextStep;
                
                if (currentStep === 0) {
                    nextBtn.disabled = !validateStep0();
                } else {
                    nextBtn.disabled = false;
                }
            }
        }

        // Form Validation
        function validateStep0() {
            const region = document.getElementById('region').value;
            const infrastructureType = document.getElementById('infrastructureType').value;
            const description = document.getElementById('description').value;
            const iamCredentials = document.getElementById('iamCredentials').value;
            
            return region && infrastructureType && description && iamCredentials;
        }

        function loadFormData() {
            document.getElementById('region').addEventListener('change', function(e) {
                config.region = e.target.value;
                updateNavigation();
            });
            
            document.getElementById('infrastructureType').addEventListener('change', function(e) {
                config.infrastructureType = e.target.value;
                updateNavigation();
            });
            
            document.getElementById('description').addEventListener('input', function(e) {
                config.description = e.target.value;
                updateNavigation();
            });
            
            document.getElementById('iamCredentials').addEventListener('input', function(e) {
                config.iamCredentials = e.target.value;
                updateNavigation();
            });
        }

        function resetForm() {
            document.getElementById('region').value = '';
            document.getElementById('infrastructureType').value = '';
            document.getElementById('description').value = '';
            document.getElementById('iamCredentials').value = '';
            
            config.region = '';
            config.infrastructureType = '';
            config.description = '';
            config.iamCredentials = '';
            
            // Reset CLI generation
            document.getElementById('generateContainer').style.display = 'flex';
            document.getElementById('generatedContent').classList.remove('show');
            
            // Reset analysis
            document.getElementById('analysisIdle').style.display = 'block';
            document.getElementById('analysisProgress').classList.add('hidden');
            document.getElementById('analysisResults').classList.add('hidden');
            document.getElementById('analysisProgressBar').style.width = '0%';
            
            // Reset execution
            document.getElementById('executionIdle').style.display = 'block';
            document.getElementById('executionSteps').classList.add('hidden');
        }

        // CLI Generation
        function generateCLI() {
            const btn = document.getElementById('generateBtn');
            btn.innerHTML = '<svg class="spinner" width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z" opacity="0.3"/><path d="M12 2v4c3.31 0 6 2.69 6 6h4c0-5.52-4.48-10-10-10z"/></svg> 생성 중...';
            btn.disabled = true;
            
            setTimeout(() => {
                document.getElementById('generateContainer').style.display = 'none';
                document.getElementById('generatedContent').classList.add('show');
                
                const policyJSON = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [`${config.infrastructureType}:*`],
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {
                                    "aws:RequestedRegion": config.region
                                }
                            }
                        }
                    ]
                };
                
                const cliCommand = `# AI가 생성한 IAM 정책
aws iam create-policy \\
  --policy-name AutoGenerated-${config.infrastructureType}-Policy \\
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["${config.infrastructureType}:*"],
        "Resource": "*"
      }
    ]
  }'

# CLI 명령어
aws ${config.infrastructureType} create \\
  --region ${config.region} \\
  --name ${config.infrastructureType}-instance \\
  --description "${config.description}"`;
                
                document.getElementById('generatedJSON').textContent = JSON.stringify(policyJSON, null, 2);
                document.getElementById('generatedCLI').textContent = cliCommand;
                
                btn.innerHTML = 'CLI 생성하기';
                btn.disabled = false;
            }, 2000);
        }

        function regenerateCLI() {
            document.getElementById('generateContainer').style.display = 'flex';
            document.getElementById('generatedContent').classList.remove('show');
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
            // API 호출
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
        // ⚠️ 지금은 그냥 로그만
                showAnalysisResults(data);
        // 나중에 data로 vulnerabilities 대체 가능
            })
            .catch(err => {
                console.error('취약점 분석 API 에러:', err);
            });
            /////////
        }


        function showAnalysisResults(data) {
            document.getElementById('analysisProgress').classList.add('hidden');
            document.getElementById('analysisResults').classList.remove('hidden');

    // 1️⃣ 인프라 JSON 출력
    if (data.infrastructure) {
        document.getElementById('infrastructureJSON').textContent =
            JSON.stringify(data.infrastructure, null, 2);
    }

    // 2️⃣ 분석 결과 출력
    const vulnerabilities = (data.analysis && data.analysis.vulnerabilities) || [];
    const container = document.getElementById('vulnerabilityList');
    container.innerHTML = '';

    vulnerabilities.forEach((vuln, index) => {
        const card = document.createElement('div');
        card.className = `vulnerability-card ${vuln.severity || ''}`;

        const badgeClass = vuln.severity === 'high'
            ? 'badge-danger'
            : vuln.severity === 'medium'
                ? 'badge-warning'
                : 'badge-secondary';

        // 공격 경로 HTML 생성
        let attackPathHTML = '<div class="attack-path">';
        if (vuln.attackPath) {
            vuln.attackPath.forEach((step, i) => {
                attackPathHTML += `<span class="attack-path-item">${step}</span>`;
                if (i < vuln.attackPath.length - 1) attackPathHTML += '<span class="attack-path-arrow">→</span>';
            });
        }
        attackPathHTML += '</div>';

        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                <h3 style="font-weight: 600;">${index + 1}. ${vuln.title || '분석 결과'}</h3>
                <div style="display: flex; gap: 8px;">
                    <span class="badge ${badgeClass}">${(vuln.severity || '').toUpperCase()}</span>
                    <span class="badge badge-secondary">CVSS: ${vuln.cvss_score || '-'}</span>
                </div>
            </div>

            <div class="vuln-section">
                <p class="vuln-label">취약점 설명 / 분석 내용</p>
                <pre style="white-space: pre-wrap; word-break: break-word;">${vuln.description || JSON.stringify(vuln, null, 2)}</pre>
            </div>

            <div class="vuln-section">
                <p class="vuln-label">공격 경로</p>
                ${attackPathHTML}
            </div>

            <div class="vuln-section">
                <p class="vuln-label">잠재적 영향</p>
                <p>${vuln.impact || '-'}</p>
            </div>

            <div class="recommendation-box">
                <p class="recommendation-title">✓ 권장 사항</p>
                <p class="recommendation-text">${vuln.recommendation || '-'}</p>
            </div>
        `;

        container.appendChild(card);
    });
            
            // // 인프라 JSON 예시
            // const infrastructureData = {
            //     "account_id": "123456789012",
            //     "region": config.region,
            //     "existing_resources": {
            //         "vpc": {
            //             "id": "vpc-0abc123def456",
            //             "cidr": "10.0.0.0/16",
            //             "subnets": ["subnet-1", "subnet-2"]
            //         },
            //         "iam_roles": [
            //             {
            //                 "name": "LambdaExecutionRole",
            //                 "policies": ["AWSLambdaBasicExecutionRole", "S3FullAccess"]
            //             },
            //             {
            //                 "name": "EC2InstanceRole",
            //                 "policies": ["EC2ReadOnlyAccess"]
            //             }
            //         ],
            //         "s3_buckets": [
            //             {
            //                 "name": "company-data-bucket",
            //                 "encryption": "AES256",
            //                 "public_access": false
            //             }
            //         ],
            //         "security_groups": [
            //             {
            //                 "id": "sg-0abc123",
            //                 "name": "web-server-sg",
            //                 "inbound_rules": [
            //                     {"port": 80, "source": "0.0.0.0/0"},
            //                     {"port": 443, "source": "0.0.0.0/0"}
            //                 ]
            //             }
            //         ]
            //     },
            //     "new_resource": {
            //         "type": config.infrastructureType,
            //         "region": config.region,
            //         "description": config.description,
            //         "iam_policy": {
            //             "Action": [config.infrastructureType + ":*"],
            //             "Resource": "*"
            //         }
            //     },
            //     "analysis_timestamp": new Date().toISOString(),
            //     "risk_score": 7.5,
            //     "compliance_status": "Non-Compliant"
            // };
            
            // document.getElementById('infrastructureJSON').textContent = JSON.stringify(infrastructureData, null, 2);
            
        // 취약점 분석 예시
            // const vulnerabilities = [
            //     {
            //         severity: 'high',
            //         title: '권한 상승 가능성 탐지',
            //         description: '새로운 IAM 정책이 기존 인프라와 결합될 때 관리자 권한 상승 경로가 발견되었습니다.',
            //         attackPath: ['User A', 'Lambda Execution Role', 'S3 Full Access', 'Admin Policy'],
            //         recommendation: 'S3 버킷 접근 권한을 특정 리소스로 제한하세요.',
            //         impact: '공격자가 Lambda 실행 역할을 통해 S3 전체 접근 권한을 얻고, 이를 악용하여 관리자 정책으로 권한을 상승시킬 수 있습니다.',
            //         cvss_score: 8.5
            //     },
            //     {
            //         severity: 'medium',
            //         title: '과도한 권한 부여',
            //         description: '생성되는 리소스에 필요 이상의 권한이 부여되어 있습니다.',
            //         attackPath: ['New Resource', 'Wildcard Permissions', 'All Services'],
            //         recommendation: '최소 권한 원칙에 따라 필요한 권한만 부여하세요.',
            //         impact: '와일드카드(*) 권한 사용으로 인해 필요 이상의 서비스 및 리소스에 접근할 수 있습니다.',
            //         cvss_score: 5.5
            //     },
            //     {
            //         severity: 'low',
            //         title: '리전 간 접근 제한 없음',
            //         description: '특정 리전에만 접근해야 하지만 모든 리전에 대한 접근이 허용됩니다.',
            //         attackPath: ['IAM Policy', 'No Region Restriction', 'Global Access'],
            //         recommendation: 'aws:RequestedRegion 조건을 사용하여 리전을 제한하세요.',
            //         impact: '불필요한 리전에서의 리소스 생성 및 접근이 가능하여 관리 복잡도가 증가합니다.',
            //         cvss_score: 3.2
            //     }
            // ];
            
            // const container = document.getElementById('vulnerabilityList');
            // container.innerHTML = '';
            
            // vulnerabilities.forEach((vuln, index) => {
            //     const card = document.createElement('div');
            //     card.className = `vulnerability-card ${vuln.severity}`;
                
            //     const badgeClass = vuln.severity === 'high' ? 'badge-danger' : vuln.severity === 'medium' ? 'badge-warning' : 'badge-secondary';
                
            //     let attackPathHTML = '<div class="attack-path">';
            //     vuln.attackPath.forEach((step, i) => {
            //         attackPathHTML += `<span class="attack-path-item">${step}</span>`;
            //         if (i < vuln.attackPath.length - 1) {
            //             attackPathHTML += '<span class="attack-path-arrow">→</span>';
            //         }
            //     });
            //     attackPathHTML += '</div>';
                
            //     card.innerHTML = `
            //         <div style="display: flex; align-items: start; justify-content: space-between; margin-bottom: 12px;">
            //             <div>
            //                 <h3 style="font-weight: 600; margin-bottom: 4px;">${index + 1}. ${vuln.title}</h3>
            //                 <div style="display: flex; gap: 8px; margin-top: 8px;">
            //                     <span class="badge ${badgeClass}">${vuln.severity.toUpperCase()}</span>
            //                     <span class="badge badge-secondary">CVSS: ${vuln.cvss_score}</span>
            //                 </div>
            //             </div>
            //         </div>
            //         <div style="padding: 12px; background: white; border-radius: 6px; margin-bottom: 12px;">
            //             <p style="font-weight: 500; font-size: 13px; color: #232F3E; margin-bottom: 4px;">취약점 설명</p>
            //             <p style="color: #374151; font-size: 14px;">${vuln.description}</p>
            //         </div>
            //         <div style="padding: 12px; background: white; border-radius: 6px; margin-bottom: 12px;">
            //             <p style="font-weight: 500; font-size: 13px; color: #232F3E; margin-bottom: 8px;">공격 경로 (Attack Path)</p>
            //             ${attackPathHTML}
            //         </div>
            //         <div style="padding: 12px; background: white; border-radius: 6px; margin-bottom: 12px;">
            //             <p style="font-weight: 500; font-size: 13px; color: #232F3E; margin-bottom: 4px;">잠재적 영향</p>
            //             <p style="color: #6B7280; font-size: 13px;">${vuln.impact}</p>
            //         </div>
            //         <div class="recommendation-box">
            //             <p class="recommendation-title">✓ 권장 사항</p>
            //             <p class="recommendation-text">${vuln.recommendation}</p>
            //         </div>
            //     `;
                
            //     container.appendChild(card);
            // });
        }

        // Execution
        function executeProcess() {
            document.getElementById('executionIdle').style.display = 'none';
            document.getElementById('executionSteps').classList.remove('hidden');
            
            const steps = [
                { name: 'IAM 자격 증명 생성', delay: 1500 },
                { name: 'AI 생성 로깅', delay: 3000 },
                { name: '리소스 생성 실행', delay: 4500 },
                { name: 'CloudTrail 로그 검증', delay: 6000 },
                { name: '임시 자격 증명 삭제', delay: 7500 }
            ];
            
            const container = document.getElementById('stepsContainer');
            container.innerHTML = '';
            
            steps.forEach((step, index) => {
                const stepDiv = document.createElement('div');
                stepDiv.className = 'execution-step';
                stepDiv.id = `exec-step-${index}`;
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
                
                setTimeout(() => {
                    const icon = document.getElementById(`icon-${index}`);
                    icon.className = 'step-icon';
                    icon.innerHTML = '<svg width="20" height="20" fill="#16a34a" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>';
                    
                    const now = new Date().toLocaleTimeString('ko-KR');
                    document.getElementById(`time-${index}`).textContent = now;
                    document.getElementById(`status-${index}`).style.display = 'block';
                    
                    if (index === steps.length - 1) {
                        document.getElementById('executionComplete').classList.remove('hidden');
                    }
                }, step.delay);
            });
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

        function populateLoggingData() {
            // AI Logs
            const aiLogs = [
                { timestamp: '2026-01-14 14:32:15', action: 'IAM_CREDENTIAL_CREATE', user: 'AI-System', resource: 'arn:aws:iam::123456789012:user/ai-temp-user-7d8f9', status: 'SUCCESS', details: 'AI가 임시 IAM 사용자 생성' },
                { timestamp: '2026-01-14 14:32:18', action: 'IAM_POLICY_ATTACH', user: 'AI-System', resource: 'AutoGenerated-ec2-Policy', status: 'SUCCESS', details: 'AI 생성 정책 연결' },
                { timestamp: '2026-01-14 14:32:22', action: 'EC2_INSTANCE_CREATE', user: 'ai-temp-user-7d8f9', resource: 'i-0a1b2c3d4e5f6g7h8', status: 'SUCCESS', details: 'EC2 인스턴스 생성 완료' },
                { timestamp: '2026-01-14 14:32:35', action: 'IAM_CREDENTIAL_DELETE', user: 'AI-System', resource: 'arn:aws:iam::123456789012:user/ai-temp-user-7d8f9', status: 'SUCCESS', details: '임시 자격 증명 삭제 완료' }
            ];
            
            const aiLogsContainer = document.getElementById('aiLogsContent');
            aiLogsContainer.innerHTML = '';
            
            aiLogs.forEach(log => {
                const entry = document.createElement('div');
                entry.className = 'log-entry';
                entry.innerHTML = `
                    <div class="log-header">
                        <div style="display: flex; gap: 8px;">
                            <span class="badge badge-secondary">${log.action}</span>
                            <span class="badge badge-success">성공</span>
                        </div>
                        <span class="log-time">${log.timestamp}</span>
                    </div>
                    <div class="log-details">
                        <p><span style="color: #6B7280;">사용자:</span> <span style="font-family: monospace;">${log.user}</span></p>
                        <p><span style="color: #6B7280;">리소스:</span> <span style="font-family: monospace; font-size: 12px;">${log.resource}</span></p>
                        <p style="color: #374151;">${log.details}</p>
                    </div>
                `;
                aiLogsContainer.appendChild(entry);
            });
            
            // CloudTrail Logs
            const cloudTrailLogs = [
                { timestamp: '2026-01-14 14:32:15', eventName: 'CreateUser', eventSource: 'iam.amazonaws.com', userIdentity: 'AI-System', sourceIP: '192.0.2.1', userAgent: 'AWS-Internal', status: '✓ 검증됨' },
                { timestamp: '2026-01-14 14:32:18', eventName: 'AttachUserPolicy', eventSource: 'iam.amazonaws.com', userIdentity: 'AI-System', sourceIP: '192.0.2.1', userAgent: 'AWS-Internal', status: '✓ 검증됨' },
                { timestamp: '2026-01-14 14:32:22', eventName: 'RunInstances', eventSource: 'ec2.amazonaws.com', userIdentity: 'ai-temp-user-7d8f9', sourceIP: '192.0.2.1', userAgent: 'aws-cli/2.0', status: '✓ 검증됨' },
                { timestamp: '2026-01-14 14:32:35', eventName: 'DeleteUser', eventSource: 'iam.amazonaws.com', userIdentity: 'AI-System', sourceIP: '192.0.2.1', userAgent: 'AWS-Internal', status: '✓ 검증됨' }
            ];
            
            const cloudTrailContainer = document.getElementById('cloudtrailContent');
            cloudTrailContainer.innerHTML = '';
            
            cloudTrailLogs.forEach(log => {
                const entry = document.createElement('div');
                entry.className = 'log-entry';
                entry.innerHTML = `
                    <div class="log-header">
                        <div style="display: flex; gap: 8px;">
                            <span class="badge badge-secondary">${log.eventName}</span>
                            <span class="badge badge-success">${log.status}</span>
                        </div>
                        <span class="log-time">${log.timestamp}</span>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px;">
                        <p><span style="color: #6B7280;">소스:</span> <span style="font-family: monospace; font-size: 12px;">${log.eventSource}</span></p>
                        <p><span style="color: #6B7280;">사용자:</span> <span style="font-family: monospace; font-size: 12px;">${log.userIdentity}</span></p>
                        <p><span style="color: #6B7280;">IP:</span> <span style="font-family: monospace;">${log.sourceIP}</span></p>
                        <p><span style="color: #6B7280;">Agent:</span> <span style="font-family: monospace; font-size: 12px;">${log.userAgent}</span></p>
                    </div>
                `;
                cloudTrailContainer.appendChild(entry);
            });
            
            // Alerts
            const alerts = [
                { type: 'info', message: '모든 AI 생성 활동이 정상적으로 로깅되었습니다', timestamp: '2026-01-14 14:32:40' },
                { type: 'success', message: 'CloudTrail 로그와 AI 로그가 일치합니다', timestamp: '2026-01-14 14:32:40' },
                { type: 'info', message: '임시 자격 증명이 허용된 CLI 명령만 실행했습니다', timestamp: '2026-01-14 14:32:40' }
            ];
            
            const alertsContainer = document.getElementById('alertsContent');
            alertsContainer.innerHTML = '';
            
            alerts.forEach(alert => {
                const alertDiv = document.createElement('div');
                alertDiv.style.cssText = 'display: flex; align-items: start; gap: 12px; padding: 12px; background: #F9FAFB; border-radius: 6px; border: 1px solid #E5E7EB; margin-bottom: 12px;';
                
                let icon = '';
                if (alert.type === 'success') {
                    icon = '<svg width="16" height="16" fill="#16a34a" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>';
                } else {
                    icon = '<svg width="16" height="16" fill="#2563EB" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>';
                }
                
                alertDiv.innerHTML = `
                    ${icon}
                    <div style="flex: 1;">
                        <p style="font-size: 14px; font-weight: 500; margin-bottom: 4px;">${alert.message}</p>
                        <p style="font-size: 12px; color: #6B7280;">${alert.timestamp}</p>
                    </div>
                `;
                alertsContainer.appendChild(alertDiv);
            });
        }