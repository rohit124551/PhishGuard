document.addEventListener('DOMContentLoaded', () => {
    console.log('PhishGuard loaded');

    const scanBtn = document.querySelector('.scan-btn');
    const urlInput = document.querySelector('.input-field');
    const resultContainer = document.getElementById('resultContainer');
    const scoreValue = document.getElementById('scoreValue');
    const resultTitle = document.getElementById('resultTitle');
    const riskLabel = document.getElementById('riskLabel');
    const riskList = document.getElementById('riskList');
    const scoreCircle = document.querySelector('.score-circle');

    // Dashboard Elements
    const navBtns = document.querySelectorAll('.nav-btn');
    const sections = document.querySelectorAll('.content-section');
    const historyTableBody = document.getElementById('historyTableBody');
    const noHistoryMsg = document.getElementById('noHistoryMsg');

    // Stats Elements
    const totalScansEl = document.getElementById('totalScans');
    const totalThreatsEl = document.getElementById('totalThreats');
    const totalSafeEl = document.getElementById('totalSafe');
    const riskChart = document.getElementById('riskChart');

    // Modal Elements
    const detailsModal = document.getElementById('detailsModal');
    const modalBody = document.getElementById('modalBody');
    const closeModal = document.querySelector('.close-modal');

    let scoreInterval; // Store interval ID to prevent overlaps

    // Advanced Heuristic Data
    const legitimateDomains = [
        'google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
        'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'whatsapp.com',
        'telegram.org', 'paypal.com', 'chase.com', 'bankofamerica.com'
    ];

    const homoglyphMap = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g',
        'i': 'l', 'v': 'u', 'w': 'vv'
    };

    if (scanBtn && urlInput) {
        scanBtn.addEventListener('click', () => {
            // Reset UI immediately
            resultContainer.classList.add('hidden');
            urlInput.classList.remove('error');

            const url = urlInput.value.trim();
            // Basic Input Validation
            if (!url) {
                showInputError('Please enter a URL to scan.');
                return;
            }
            // Check for valid URL format (simple regex for UX, full check later)
            if (!url.includes('.')) {
                showInputError('Please enter a valid URL (e.g., example.com).');
                return;
            }

            analyzeURL(url);
        });

        // Clear error on input
        urlInput.addEventListener('input', () => {
            urlInput.classList.remove('error');
        });
    }

    function showInputError(message) {
        urlInput.placeholder = message;
        urlInput.classList.add('error');
        urlInput.value = '';
        setTimeout(() => {
            urlInput.placeholder = 'Paste URL here to scan...';
        }, 3000);
    }

    function calculateEntropy(str) {
        const charCounts = {};
        for (const char of str) {
            charCounts[char] = (charCounts[char] || 0) + 1;
        }
        const totalChars = str.length;
        let entropy = 0;
        for (const char in charCounts) {
            const probability = charCounts[char] / totalChars;
            entropy -= probability * Math.log2(probability);
        }
        return entropy;
    }

    function analyzeURL(url) {
        // Reset UI
        resultContainer.classList.remove('hidden');
        riskList.innerHTML = '';
        scoreCircle.className = 'score-circle'; // proper reset
        resultTitle.textContent = 'Scanning...';
        riskLabel.textContent = '';

        // Normalize URL
        let urlObj;
        let protocol = 'http:'; // default if missing
        try {
            // Handle missing protocol for parsing
            let fullUrl = url;
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                fullUrl = `http://${url}`; // Assume unsafe if unspecified, or just for parsing
            }
            urlObj = new URL(fullUrl);
            protocol = urlObj.protocol;

            // If user explicitly typed https, update our 'protocol' var from input if needed
            // But URL() parser handles it.
        } catch (e) {
            displayResult(0, ['Invalid URL Format'], 'Error', 'invalid');
            return;
        }

        const hostname = urlObj.hostname;
        const pathname = urlObj.pathname;
        let currentRisk = 0;
        let risks = [];

        const addRisk = (score, description) => {
            risks.push(description);
            return score;
        };

        // --- Heuristics ---

        // 1. IP Address
        if (/^(\d+\.){3}\d+$/.test(hostname)) {
            currentRisk += addRisk(35, 'IP Address used instead of Domain Name');
        }

        // 2. Protocol Check (HTTP vs HTTPS)
        if (protocol === 'http:') {
            currentRisk += addRisk(15, 'Insecure Protocol (HTTP instead of HTTPS)');
        }

        // 3. @ Symbol
        if (url.includes('@')) {
            currentRisk += addRisk(25, '@ Symbol found (potential credential theft)');
        }

        // 4. Typosquatting
        let isHomoglyph = false;
        const baseDomain = hostname.split('.').slice(-2).join('.');

        for (const legitDomain of legitimateDomains) {
            if (baseDomain !== legitDomain && baseDomain.length === legitDomain.length) {
                let diffCount = 0;
                for (let i = 0; i < baseDomain.length; i++) {
                    const char1 = baseDomain[i];
                    const char2 = legitDomain[i];
                    if (char1 !== char2 && homoglyphMap[char1] !== char2 && homoglyphMap[char2] !== char1) {
                        diffCount++;
                    }
                }
                if (diffCount <= 1) {
                    isHomoglyph = true;
                    if (!hostname.includes(legitDomain)) break;
                    else isHomoglyph = false;
                }
            }
        }
        if (isHomoglyph) {
            currentRisk += addRisk(30, 'Potential Typosquatting (mimics popular domain)');
        }

        // 5. URL Length
        if (url.length > 75) {
            currentRisk += addRisk(10, 'Suspiciously long URL (>75 chars)');
        }

        // 6. Entropy
        const entropy = calculateEntropy(hostname);
        if (entropy > 4.5) { // Increased threshold slightly
            currentRisk += addRisk(15, 'High Randomness in Hostname');
        }

        // 7. Keywords
        const suspiciousKeywords = ['login', 'secure', 'account', 'verify', 'update', 'banking', 'paypal', 'admin', 'wallet', 'confirm'];
        if (suspiciousKeywords.some(k => pathname.toLowerCase().includes(k) || hostname.toLowerCase().includes(k))) {
            currentRisk += addRisk(10, 'Sensitive keywords found in URL');
        }

        // 8. Subdomains
        const subdomainCount = hostname.split('.').length - 2;
        if (subdomainCount > 3) {
            currentRisk += addRisk(10, 'Excessive number of subdomains');
        }

        // 9. Hyphen Check
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount > 3) {
            currentRisk += addRisk(10, 'Excessive hyphens (potential obfuscation)');
        }

        // 10. TLD
        const suspiciousTLDs = ['.xyz', '.top', '.club', '.info', '.gq', '.tk', '.cn', '.ru'];
        if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
            currentRisk += addRisk(10, `Suspicious Top-Level Domain (${hostname.split('.').pop()})`);
        }

        // Calculate Score
        let safetyScore = Math.max(0, 100 - currentRisk);

        // Determine Status
        let statusTitle = '';
        let statusClass = '';
        let riskLabelText = '';

        if (safetyScore >= 80) {
            statusTitle = 'Safe URL';
            statusClass = 'status-safe';
            riskLabelText = 'Low Risk';
            if (risks.length === 0) risks.push('No obvious threats detected.');
        } else if (safetyScore >= 50) {
            statusTitle = 'Suspicious URL';
            statusClass = 'status-warning';
            riskLabelText = 'Medium Risk';
        } else {
            statusTitle = 'High Risk Phishing';
            statusClass = 'status-danger';
            riskLabelText = 'Critical Risk';
        }

        const resultData = {
            url: url,
            score: safetyScore,
            statusClass: statusClass,
            date: new Date().toLocaleString(),
            risks: risks // Save risks for details view
        };
        saveResultToHistory(resultData);

        displayResult(safetyScore, risks, statusTitle, statusClass, riskLabelText);
    }

    function displayResult(score, risks, title, statusClass, riskLabelText) {
        animateScore(score);
        resultTitle.textContent = title;
        resultTitle.className = ''; // clear previous text colors

        riskLabel.textContent = riskLabelText;
        riskLabel.className = 'risk-label'; // reset

        scoreCircle.classList.add(statusClass);

        if (statusClass === 'status-safe') {
            resultTitle.classList.add('text-safe');
            riskLabel.classList.add('text-safe');
        } else if (statusClass === 'status-warning') {
            resultTitle.classList.add('text-warning');
            riskLabel.classList.add('text-warning');
        } else {
            resultTitle.classList.add('text-danger');
            riskLabel.classList.add('text-danger');
        }

        risks.forEach(risk => {
            const li = document.createElement('li');
            const icon = document.createElement('i');
            icon.className = `fas fa-exclamation-triangle ${statusClass === 'status-safe' ? 'text-safe' : 'text-danger'}`;
            li.appendChild(icon);
            // Use createTextNode for safety against XSS if risk string contains user input
            li.appendChild(document.createTextNode(' ' + risk));
            riskList.appendChild(li);
        });
    }

    function animateScore(targetScore) {
        if (scoreInterval) clearInterval(scoreInterval);

        let currentScore = 0;
        // Immediate set if 0 to avoid delay
        scoreValue.textContent = currentScore;

        scoreInterval = setInterval(() => {
            if (currentScore >= targetScore) {
                clearInterval(scoreInterval);
                scoreValue.textContent = targetScore;
            } else {
                currentScore++;
                scoreValue.textContent = currentScore;
            }
        }, 10);
    }

    // --- Dashboard & Navigation Logic ---

    // Tab Switching
    navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all buttons
            navBtns.forEach(b => b.classList.remove('active'));
            // Add active class to clicked button
            btn.classList.add('active');

            // Hide all sections
            sections.forEach(section => {
                section.classList.remove('active-section');
                section.classList.add('hidden');
            });

            // Show target section
            const targetId = btn.getAttribute('data-target');
            const targetSection = document.getElementById(targetId);
            targetSection.classList.remove('hidden');
            targetSection.classList.add('active-section');

            // If switching to dashboard, refresh history
            if (targetId === 'dashboard-section') {
                loadHistory();
            }
        });
    });

    // Save Result to LocalStorage
    function saveResultToHistory(result) {
        let history = JSON.parse(localStorage.getItem('phishGuardHistory')) || [];
        // Add new result to the beginning
        history.unshift(result);
        // Limit history to last 50 items
        if (history.length > 50) history.pop();
        localStorage.setItem('phishGuardHistory', JSON.stringify(history));
    }

    // Load History & Dashboard Data
    function loadHistory() {
        const history = JSON.parse(localStorage.getItem('phishGuardHistory')) || [];

        // Update Stats
        const totalScans = history.length;
        const totalThreats = history.filter(h => h.statusClass === 'status-danger').length;
        const totalSafe = history.filter(h => h.statusClass === 'status-safe').length;

        if (totalScansEl) totalScansEl.textContent = totalScans;
        if (totalThreatsEl) totalThreatsEl.textContent = totalThreats;
        if (totalSafeEl) totalSafeEl.textContent = totalSafe;

        // Render Chart
        renderChart(Math.min(10, totalScans), history.slice(0, 10));

        // Render Table
        historyTableBody.innerHTML = '';
        if (history.length === 0) {
            noHistoryMsg.classList.remove('hidden');
            return;
        }
        noHistoryMsg.classList.add('hidden');

        history.forEach((item, index) => {
            const tr = document.createElement('tr');

            // Format status pill
            let pillClass = '';
            let statusText = '';
            if (item.statusClass === 'status-safe') {
                pillClass = 'status-safe-pill'; // Using original class name from HTML/CSS if preferred, but new CSS has ti-pill variants. 
                // Wait, previous CSS update added .ti-pill.safe/warning/danger.
                // Let's check style.css classes. 
                // In Step 48 logic: .ti-pill.safe, .ti-pill.warning, .ti-pill.danger
                pillClass = 'safe';
                statusText = 'SAFE';
            } else if (item.statusClass === 'status-warning') {
                pillClass = 'warning';
                statusText = 'SUSPICIOUS';
            } else {
                pillClass = 'danger';
                statusText = 'PHISHING';
            }

            // Note: The new CSS update used .ti-pill and .safe/warning/danger classes. 
            // Previous JS used .status-safe-pill etc. 
            // I will use the new classes compatible with the new CSS.

            tr.innerHTML = `
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.url}">${item.url}</td>
                <td><span class="ti-pill ${pillClass}">${statusText}</span></td>
                <td>${item.date}</td>
                <td>${item.score}%</td>
                <td><button class="view-details-btn" data-index="${index}">View Details</button></td>
            `;
            historyTableBody.appendChild(tr);
        });

        // Add Event Listeners for details buttons
        document.querySelectorAll('.view-details-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = e.target.getAttribute('data-index');
                showDetails(history[index]);
            });
        });
    }

    function renderChart(count, latestHistory) {
        if (!riskChart) return;
        riskChart.innerHTML = '';
        if (count === 0) {
            riskChart.innerHTML = '<div class="chart-placeholder">No Data Available</div>';
            return;
        }

        // Aggregate last 10 scans
        let safeCount = 0;
        let suspCount = 0;
        let dangCount = 0;

        latestHistory.forEach(h => {
            if (h.statusClass === 'status-safe') safeCount++;
            else if (h.statusClass === 'status-warning') suspCount++;
            else dangCount++;
        });

        // Calculate heights (max 100%)
        const max = Math.max(safeCount, suspCount, dangCount, 1);

        const createBar = (label, count, typeClass) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'chart-bar-wrapper';

            // height percentage
            const heightPerc = (count / max) * 100;

            wrapper.innerHTML = `
                <div class="chart-bar ${typeClass}" style="height: ${heightPerc}%;"></div>
                <span class="bar-count">${count}</span>
                <span class="bar-label">${label}</span>
            `;
            return wrapper;
        };

        riskChart.appendChild(createBar('SAFE', safeCount, 'bar-safe'));
        riskChart.appendChild(createBar('SUSPICIOUS', suspCount, 'bar-suspicious'));
        riskChart.appendChild(createBar('PHISHING', dangCount, 'bar-danger'));
    }

    function showDetails(item) {
        let pillClass = '';
        let statusText = '';
        if (item.statusClass === 'status-safe') {
            pillClass = 'safe';
            statusText = 'SAFE';
        } else if (item.statusClass === 'status-warning') {
            pillClass = 'warning';
            statusText = 'SUSPICIOUS';
        } else {
            pillClass = 'danger';
            statusText = 'PHISHING';
        }

        modalBody.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">Scanned URL</span>
                <div class="detail-value" style="color: var(--cyber-blue); word-break: break-all;">${item.url}</div>
            </div>
            <div class="detail-row">
                <span class="detail-label">Status</span>
                <span class="ti-pill ${pillClass}">${statusText}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Risk Score</span>
                <span class="detail-value">${item.score}%</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Scan Date</span>
                <span class="detail-value">${item.date}</span>
            </div>
            <div>
                <span class="detail-label">Risk Factors Detected</span>
                ${item.risks && item.risks.length > 0 ?
                `<ul class="risk-list-detail">
                        ${item.risks.map(r => `<li>${r}</li>`).join('')}
                    </ul>` :
                '<div style="color: rgba(255,255,255,0.5); font-style:italic;">No specific threats detected.</div>'
            }
            </div>
        `;
        detailsModal.classList.remove('hidden');
    }

    if (closeModal) {
        closeModal.addEventListener('click', () => {
            detailsModal.classList.add('hidden');
        });
    }

    if (detailsModal) {
        window.addEventListener('click', (e) => {
            if (e.target === detailsModal) {
                detailsModal.classList.add('hidden');
            }
        });
    }

});
