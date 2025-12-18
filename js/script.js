document.addEventListener('DOMContentLoaded', () => {
    console.log('PhishGuard loaded');

    const scanBtn = document.querySelector('.scan-btn');
    const urlInput = document.querySelector('.input-field');
    const resultContainer = document.getElementById('resultContainer');
    const scoreValue = document.getElementById('scoreValue');
    const resultTitle = document.getElementById('resultTitle');
    const riskList = document.getElementById('riskList');
    const scoreCircle = document.querySelector('.score-circle');

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

    function analyzeURL(url) {
        // Reset UI
        resultContainer.classList.remove('hidden');
        riskList.innerHTML = '';
        scoreCircle.className = 'score-circle'; // reset classes

        let score = 100;
        let risks = [];

        // 1. Check for IP Address
        const ipRegex = /^(http|https):\/\/(\d{1,3}\.){3}\d{1,3}/;
        if (ipRegex.test(url)) {
            score -= 50;
            risks.push("URL uses an IP address instead of a domain name.");
        }

        // 2. Length Check
        if (url.length > 75) {
            score -= 20;
            risks.push("URL is suspiciously long (> 75 characters).");
        }

        // 3. @ Symbol Check
        if (url.includes('@')) {
            score -= 40;
            risks.push("URL contains an '@' symbol, often used to obscure the destination.");
        }

        // 4. Keyword Analysis
        const suspiciousKeywords = ['login', 'secure', 'account', 'update', 'banking', 'verify', 'wallet'];
        suspiciousKeywords.forEach(keyword => {
            if (url.toLowerCase().includes(keyword)) {
                score -= 10;
                risks.push(`URL contains suspicious keyword: "${keyword}"`);
            }
        });

        // 5. TLD Check (Simplified)
        const suspiciousTLDs = ['.xyz', '.top', '.club', '.info', '.gq', '.tk'];
        suspiciousTLDs.forEach(tld => {
            if (url.toLowerCase().endsWith(tld) || url.toLowerCase().includes(tld + '/')) {
                score -= 10;
                risks.push(`URL uses a suspicious TLD: "${tld}"`);
            }
        });

        // Cap score
        if (score < 0) score = 0;

        // UI Updates based on score
        animateScore(score);

        if (score >= 80) {
            resultTitle.innerHTML = '<span class="text-safe">Safe URL</span>';
            resultTitle.style.color = 'var(--success-color)';
            scoreCircle.classList.add('status-safe');
            if (risks.length === 0) {
                const li = document.createElement('li');
                li.innerHTML = '<i class="fas fa-check-circle" style="color: var(--success-color)"></i> No obvious threats detected.';
                riskList.appendChild(li);
            }
        } else if (score >= 50) {
            resultTitle.innerHTML = '<span class="text-warning">Suspicious URL</span>';
            scoreCircle.style.borderColor = '#f7b731';
            scoreCircle.style.boxShadow = '0 0 20px rgba(247, 183, 49, 0.3)';
        } else {
            resultTitle.innerHTML = '<span class="text-danger">High Risk Phishing</span>';
            scoreCircle.classList.add('status-danger');
        }

        // Populate risks
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
