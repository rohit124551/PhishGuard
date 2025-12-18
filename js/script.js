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
});
