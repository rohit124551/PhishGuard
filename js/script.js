document.addEventListener('DOMContentLoaded', () => {
    console.log('PhishGuard loaded');

    const scanBtn = document.querySelector('.scan-btn');
    const urlInput = document.querySelector('.input-field');
    const resultContainer = document.getElementById('resultContainer');
    const scoreValue = document.getElementById('scoreValue');
    const resultTitle = document.getElementById('resultTitle');
    const riskList = document.getElementById('riskList');
    const scoreCircle = document.querySelector('.score-circle');

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
            const url = urlInput.value.trim();
            if (url) {
                analyzeURL(url);
            } else {
                urlInput.focus();
                urlInput.classList.add('shake');
                setTimeout(() => urlInput.classList.remove('shake'), 500);
            }
        });
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
        scoreCircle.className = 'score-circle'; // reset classes

        // Normalize URL
        let urlObj;
        try {
            const fullUrl = url.startsWith('http') ? url : `https://${url}`;
            urlObj = new URL(fullUrl);
        } catch (e) {
            displayResult(0, ['Invalid URL Format'], 'High Risk Phishing');
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

        // 1. IP Address in Hostname
        if (/^(\d+\.){3}\d+$/.test(hostname)) {
            currentRisk += addRisk(35, 'IP Address used instead of Domain Name');
        }

        // 2. @ Symbol Check
        if (url.includes('@')) {
            currentRisk += addRisk(25, '@ Symbol found (potential credential theft)');
        }

        // 3. Typosquatting/Homoglyph Detection
        let isHomoglyph = false;
        const baseDomain = hostname.split('.').slice(-2).join('.'); // roughly get domain.tld

        for (const legitDomain of legitimateDomains) {
            if (baseDomain !== legitDomain && baseDomain.length === legitDomain.length) {
                let diffCount = 0;
                for (let i = 0; i < baseDomain.length; i++) {
                    const char1 = baseDomain[i];
                    const char2 = legitDomain[i];
                    // Check if characters are different AND not a known homoglyph mapping
                    if (char1 !== char2 && homoglyphMap[char1] !== char2 && homoglyphMap[char2] !== char1) {
                        diffCount++;
                    }
                }
                if (diffCount <= 1) {
                    isHomoglyph = true;
                    // Double check if it's not just the legit domain
                    if (!hostname.includes(legitDomain)) {
                        break;
                    } else {
                        isHomoglyph = false; // It IS the legitimate domain (e.g. sub.google.com)
                    }
                }
            }
        }

        if (isHomoglyph) {
            currentRisk += addRisk(30, 'Potential Typosquatting (mimics popular domain)');
        }

        // 4. URL Length
        if (url.length > 75) {
            currentRisk += addRisk(10, 'Suspiciously long URL (>75 chars)');
        }

        // 5. Hostname Entropy
        const entropy = calculateEntropy(hostname);
        if (entropy > 3.7) {
            currentRisk += addRisk(20, 'High Randomness in Hostname (High Entropy)');
        }

        // 6. Suspicious Keywords
        const suspiciousKeywords = ['login', 'secure', 'account', 'verify', 'update', 'banking', 'paypal', 'admin', 'oauth', 'wallet', 'confirm'];
        const hasSuspiciousKeyword = suspiciousKeywords.some(keyword =>
            pathname.toLowerCase().includes(keyword) || hostname.toLowerCase().includes(keyword)
        );
        if (hasSuspiciousKeyword) {
            currentRisk += addRisk(10, 'Suspicious sensitive keywords found');
        }

        // 7. Subdomain Abuse
        const subdomainCount = hostname.split('.').length - 2;
        if (subdomainCount > 3) {
            currentRisk += addRisk(15, 'Excessive number of subdomains');
        }

        // 8. TLD Check
        const suspiciousTLDs = ['.xyz', '.top', '.club', '.info', '.gq', '.tk', '.cn'];
        if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
            currentRisk += addRisk(10, 'Suspicious Top-Level Domain (TLD)');
        }

        // Safety score calculation (inverse of risk)
        let safetyScore = Math.max(0, 100 - currentRisk);

        // Status Determination
        let statusTitle = '';
        if (safetyScore >= 80) {
            statusTitle = '<span class="text-safe">Safe URL</span>';
            if (risks.length === 0) risks.push('No obvious threats detected.');
        } else if (safetyScore >= 50) {
            statusTitle = '<span class="text-warning">Suspicious URL</span>';
        } else {
            statusTitle = '<span class="text-danger">High Risk Phishing</span>';
        }

        displayResult(safetyScore, risks, statusTitle);
    }

    function displayResult(score, risks, title) {
        animateScore(score);
        resultTitle.innerHTML = title;

        if (score >= 80) {
            scoreCircle.classList.add('status-safe');
            resultTitle.style.color = 'var(--success-color)';
        } else if (score >= 50) {
            scoreCircle.style.borderColor = '#f7b731';
            scoreCircle.style.boxShadow = '0 0 20px rgba(247, 183, 49, 0.3)';
        } else {
            scoreCircle.classList.add('status-danger');
        }

        risks.forEach(risk => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${risk}`;
            riskList.appendChild(li);
        });
    }

    function animateScore(targetScore) {
        let currentScore = 0;
        const interval = setInterval(() => {
            if (currentScore >= targetScore) {
                clearInterval(interval);
                scoreValue.textContent = targetScore;
            } else {
                currentScore++;
                scoreValue.textContent = currentScore;
            }
        }, 10);
    }
});
