"use client";

import { useState } from "react";
import Navbar from "@/components/Navbar";
import { analyzeURL, ScanResult } from "@/lib/scanner";
import UserIdentity from "@/components/UserIdentity";

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) {
      setError("Please enter a URL to scan.");
      setTimeout(() => setError(""), 3000);
      return;
    }

    setLoading(true);
    setError("");
    
    // Simulate a network delay for premium feel
    await new Promise(r => setTimeout(r, 1000));
    
    const scanResult = analyzeURL(url);
    setResult(scanResult);
    setLoading(false);

    // Save to localStorage
    const history = JSON.parse(localStorage.getItem("phishGuardHistory") || "[]");
    history.unshift(scanResult);
    localStorage.setItem("phishGuardHistory", JSON.stringify(history.slice(0, 50)));
  };

  return (
    <main style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '0 20px' }}>
      <Navbar />
      
      <div className="hero-content animate-fade-in" style={{ textAlign: 'center', maxWidth: '800px', width: '100%', marginTop: '4rem' }}>
        <h1 style={{ fontSize: '3.5rem', marginBottom: '1rem', lineHeight: '1.2' }}>
          Secure Your Digital <br />
          <span style={{ color: 'var(--accent-color)' }}>Presence</span>
        </h1>
        <p className="subtitle" style={{ fontSize: '1.2rem', color: 'rgba(255, 255, 255, 0.8)', marginBottom: '3rem' }}>
          Advanced heuristic analysis to detect potential phishing threats in real-time.
        </p>

        <div className="scanner-container glass">
          <form onSubmit={handleScan} className="input-group" style={{ display: 'flex', gap: '10px' }}>
            <div className="input-wrapper" style={{ position: 'relative', flex: 1 }}>
              <i className="fas fa-link input-icon" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'rgba(255, 255, 255, 0.5)' }}></i>
              <input
                type="url"
                className={`input-field ${error ? "error" : ""}`}
                placeholder={error || "Paste URL here to scan..."}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="scan-btn" disabled={loading}>
              {loading ? "Scanning..." : "Scan Now"}
            </button>
          </form>
        </div>

        <div className="identity-row" style={{ marginTop: '2rem', display: 'flex', justifyContent: 'center' }}>
          <div style={{ maxWidth: '400px', width: '100%' }}>
            <UserIdentity />
          </div>
        </div>

        {result && (
          <div className="result-container glass animate-fade-in" style={{ marginTop: '2rem', padding: '2rem', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '2rem', textAlign: 'left' }}>
            <div className="score-wrapper" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
              <div className={`score-circle ${result.statusClass}`} style={{ width: '100px', height: '100px', borderRadius: '50%', border: '5px solid', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '2rem', fontWeight: 700 }}>
                <span>{result.score}</span>%
              </div>
              <p className="score-label" style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'rgba(255, 255, 255, 0.6)' }}>Safety Score</p>
            </div>
            <div className="result-details" style={{ flex: 1 }}>
              <h2 style={{ fontSize: '1.5rem', marginBottom: '0.2rem', color: result.statusClass === 'status-safe' ? 'var(--success-color)' : 'var(--danger-color)' }}>
                {result.score >= 80 ? 'Safe URL' : result.score >= 50 ? 'Suspicious URL' : 'High Risk Phishing'}
              </h2>
              <p className="risk-label" style={{ fontSize: '0.9rem', fontWeight: 600, textTransform: 'uppercase', marginBottom: '1rem' }}>{result.riskLabel}</p>
              <ul style={{ listStyle: 'none' }}>
                {result.risks.map((risk, i) => (
                  <li key={i} style={{ marginBottom: '0.5rem', fontSize: '0.95rem', display: 'flex', gap: '10px' }}>
                    <i className={`fas fa-exclamation-triangle ${result.score >= 80 ? 'text-safe' : 'text-danger'}`}></i>
                    {risk}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      <style jsx>{`
        .input-field.error {
          border-color: var(--danger-color);
          box-shadow: 0 0 10px rgba(255, 75, 43, 0.2);
          animation: shake 0.5s ease-in-out;
        }
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-5px); }
          75% { transform: translateX(5px); }
        }
        .text-safe { color: var(--success-color); }
        .text-danger { color: var(--danger-color); }
        .status-safe { border-color: var(--success-color); box-shadow: 0 0 20px rgba(0, 176, 155, 0.3); }
        .status-warning { border-color: var(--warning-color); box-shadow: 0 0 20px rgba(247, 183, 49, 0.3); }
        .status-danger { border-color: var(--danger-color); box-shadow: 0 0 20px rgba(255, 75, 43, 0.3); }
      `}</style>
    </main>
  );
}
