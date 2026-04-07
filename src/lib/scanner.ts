/**
 * PhishGuard Core Heuristic Engine
 * Reusable server-side logic for URL scanning.
 */

const legitimateDomains = [
    'google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'whatsapp.com',
    'telegram.org', 'paypal.com', 'chase.com', 'bankofamerica.com'
];

const homoglyphMap: Record<string, string> = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g',
    'i': 'l', 'v': 'u', 'w': 'vv'
};

function calculateEntropy(str: string): number {
    const charCounts: Record<string, number> = {};
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

export interface ScanResult {
    url: string;
    score: number;
    risks: string[];
    riskLabel: string;
    statusClass: string;
    timestamp: string;
}

export function analyzeURL(url: string): ScanResult {
    let urlObj: URL;
    let protocol = 'http:';
    
    try {
        let fullUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            fullUrl = `http://${url}`;
        }
        urlObj = new URL(fullUrl);
        protocol = urlObj.protocol;
    } catch (e) {
        return {
            url,
            score: 0,
            risks: ['Invalid URL Format'],
            riskLabel: 'Error',
            statusClass: 'status-danger',
            timestamp: new Date().toISOString()
        };
    }

    const hostname = urlObj.hostname;
    const pathname = urlObj.pathname;
    let currentRisk = 0;
    let risks: string[] = [];

    const addRisk = (score: number, description: string) => {
        risks.push(description);
        currentRisk += score;
    };

    // 1. IP Address Usage
    if (/^(\d+\.){3}\d+$/.test(hostname)) {
        addRisk(35, 'IP Address used instead of Domain Name');
    }

    // 2. Insecure Protocol
    if (protocol === 'http:') {
        addRisk(15, 'Insecure Protocol (HTTP instead of HTTPS)');
    }

    // 3. Credential Theft Marker (@)
    if (url.includes('@')) {
        addRisk(25, '@ Symbol found (potential credential theft)');
    }

    // 4. Typosquatting Analysis
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
                break;
            }
        }
    }
    if (isHomoglyph) addRisk(30, 'Potential Typosquatting (mimics popular domain)');

    // 5. URL Complexity
    if (url.length > 75) addRisk(10, 'Suspiciously long URL (>75 chars)');
    
    const entropy = calculateEntropy(hostname);
    if (entropy > 4.5) addRisk(15, 'High Randomness in Hostname (potential DGA)');

    // 6. Keywords Verification
    const suspiciousKeywords = ['login', 'secure', 'account', 'verify', 'update', 'banking', 'paypal', 'admin', 'wallet', 'confirm'];
    if (suspiciousKeywords.some(k => pathname.toLowerCase().includes(k) || hostname.toLowerCase().includes(k))) {
        addRisk(10, 'Sensitive keywords found in URL');
    }

    // 7. Subdomains & Hyphens
    if (hostname.split('.').length - 2 > 3) addRisk(10, 'Excessive number of subdomains');
    if ((hostname.match(/-/g) || []).length > 3) addRisk(10, 'Excessive hyphens (potential obfuscation)');

    // 8. TLD Risk
    const suspiciousTLDs = ['.xyz', '.top', '.club', '.info', '.gq', '.tk', '.cn', '.ru'];
    if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        addRisk(10, `Suspicious Top-Level Domain (.${hostname.split('.').pop()})`);
    }

    // Final Calculation
    const safetyScore = Math.max(0, 100 - currentRisk);
    
    let riskLabel = 'Low Risk';
    let statusClass = 'status-safe';
    if (safetyScore < 50) {
        riskLabel = 'Critical Risk';
        statusClass = 'status-danger';
    } else if (safetyScore < 80) {
        riskLabel = 'Medium Risk';
        statusClass = 'status-warning';
    }

    return {
        url,
        score: safetyScore,
        risks: risks.length > 0 ? risks : ['No obvious threats detected.'],
        riskLabel,
        statusClass,
        timestamp: new Date().toISOString()
    };
}
