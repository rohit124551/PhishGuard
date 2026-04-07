"use client";

import { useEffect, useState } from "react";
import Navbar from "@/components/Navbar";
import { ScanResult } from "@/lib/scanner";

export default function Dashboard() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  useEffect(() => {
    const savedHistory = JSON.parse(localStorage.getItem("phishGuardHistory") || "[]");
    setHistory(savedHistory);
  }, []);

  const totalScans = history.length;
  const totalThreats = history.filter(h => h.score < 50).length;
  const totalSafe = history.filter(h => h.score >= 80).length;

  const latestScans = history.slice(0, 10);
  const maxCount = Math.max(totalSafe, totalThreats, history.length - totalSafe - totalThreats, 1);

  return (
    <main style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '0 20px' }}>
      <Navbar />

      <div className="dashboard-wrapper animate-fade-in" style={{ width: '100%', maxWidth: '1200px', padding: '2rem', marginTop: '2rem' }}>
        <h2 className="dashboard-title" style={{ textAlign: 'center', fontSize: '2rem', marginBottom: '3rem', color: 'var(--cyber-blue)', textShadow: '0 0 10px rgba(0, 210, 255, 0.5)', letterSpacing: '2px', fontWeight: 700 }}>
          THREAT INTELLIGENCE DASHBOARD
        </h2>

        {/* Stats Row */}
        <div className="stats-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '2rem', marginBottom: '3rem' }}>
          <div className="stat-card glass-blue">
            <div className="stat-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'rgba(255, 255, 255, 0.5)', marginBottom: '1rem' }}>
              <span>TOTAL SCANS EXECUTED</span>
              <i className="fas fa-chart-line"></i>
            </div>
            <div className="stat-value" style={{ fontSize: '2.2rem', fontWeight: 700, marginBottom: '0.5rem' }}>{totalScans}</div>
            <div className="stat-sub" style={{ fontSize: '0.7rem', textTransform: 'uppercase', opacity: 0.6 }}>URLS ANALYZED BY HEURISTIC ENGINE</div>
          </div>

          <div className="stat-card glass-red">
            <div className="stat-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'rgba(255, 255, 255, 0.5)', marginBottom: '1rem' }}>
              <span>MALICIOUS THREATS</span>
              <i className="fas fa-bug"></i>
            </div>
            <div className="stat-value" style={{ fontSize: '2.2rem', fontWeight: 700, marginBottom: '0.5rem' }}>{totalThreats}</div>
            <div className="stat-sub" style={{ fontSize: '0.7rem', textTransform: 'uppercase', opacity: 0.6 }}>CONFIRMED PHISHING DETECTIONS</div>
          </div>

          <div className="stat-card glass-green">
            <div className="stat-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'rgba(255, 255, 255, 0.5)', marginBottom: '1rem' }}>
              <span>TRUSTED ACCESS</span>
              <i className="fas fa-lock"></i>
            </div>
            <div className="stat-value" style={{ fontSize: '2.2rem', fontWeight: 700, marginBottom: '0.5rem' }}>{totalSafe}</div>
            <div className="stat-sub" style={{ fontSize: '0.7rem', textTransform: 'uppercase', opacity: 0.6 }}>LEGITIMATE URLS VERIFIED</div>
          </div>
        </div>

        {/* Chart Section */}
        <div className="glass-panel" style={{ padding: '2rem', borderRadius: '12px', marginBottom: '2rem', background: 'rgba(10, 14, 23, 0.7)', border: '1px solid rgba(0, 210, 255, 0.2)' }}>
          <h3 style={{ fontSize: '1rem', color: 'var(--cyber-blue)', marginBottom: '1.5rem', textTransform: 'uppercase', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', paddingBottom: '0.5rem' }}>
            RISK DISTRIBUTION OVERVIEW
          </h3>
          <div className="bar-chart" style={{ height: '150px', display: 'flex', alignItems: 'flex-end', gap: '3rem', paddingLeft: '1rem', borderLeft: '1px solid rgba(255, 255, 255, 0.1)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
            <div className="chart-bar-wrapper" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '60px', height: '100%', justifyContent: 'flex-end' }}>
              <div className="chart-bar bar-safe" style={{ height: `${(totalSafe / maxCount) * 100 || 4}%`, width: '100%', borderRadius: '4px 4px 0 0' }}></div>
              <span className="bar-label" style={{ fontSize: '0.7rem', color: 'var(--cyber-blue)', textTransform: 'uppercase', fontWeight: 600, marginTop: '10px' }}>SAFE</span>
            </div>
            <div className="chart-bar-wrapper" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '60px', height: '100%', justifyContent: 'flex-end' }}>
              <div className="chart-bar bar-danger" style={{ height: `${(totalThreats / maxCount) * 100 || 4}%`, width: '100%', borderRadius: '4px 4px 0 0' }}></div>
              <span className="bar-label" style={{ fontSize: '0.7rem', color: 'var(--cyber-blue)', textTransform: 'uppercase', fontWeight: 600, marginTop: '10px' }}>PHISHING</span>
            </div>
          </div>
        </div>

        {/* History Section */}
        <div className="glass-panel" style={{ padding: '2rem', borderRadius: '12px', background: 'rgba(10, 14, 23, 0.7)', border: '1px solid rgba(0, 210, 255, 0.2)' }}>
          <h3 style={{ fontSize: '1rem', color: 'var(--cyber-blue)', marginBottom: '1.5rem', textTransform: 'uppercase', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', paddingBottom: '0.5rem' }}>
            LATEST DETECTION HISTORY
          </h3>
          <div className="table-responsive" style={{ overflowX: 'auto' }}>
            <table className="ti-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>STATUS</th>
                  <th>DATE/TIME</th>
                  <th>SCORE</th>
                  <th>DETAILS</th>
                </tr>
              </thead>
              <tbody>
                {history.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'rgba(255,255,255,0.5)' }}>No records found.</td>
                  </tr>
                ) : (
                  history.map((item, index) => (
                    <tr key={index}>
                      <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.url}</td>
                      <td>
                        <span className={`ti-pill ${item.score >= 80 ? 'safe' : item.score >= 50 ? 'warning' : 'danger'}`}>
                          {item.score >= 80 ? 'SAFE' : item.score >= 50 ? 'SUSPICIOUS' : 'PHISHING'}
                        </span>
                      </td>
                      <td>{new Date(item.timestamp).toLocaleString()}</td>
                      <td>{item.score}%</td>
                      <td>
                        <button className="view-details-btn" onClick={() => setSelectedScan(item)}>View Report</button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Details Modal */}
      {selectedScan && (
        <div className="modal" style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', background: 'rgba(0,0,0,0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, backdropFilter: 'blur(5px)' }}>
          <div className="modal-content glass animate-fade-in" style={{ width: '90%', maxWidth: '600px', borderRadius: '12px', background: '#0f0c29', border: '1px solid var(--cyber-blue)', overflow: 'hidden' }}>
            <div className="modal-header" style={{ padding: '1.5rem', borderBottom: '1px solid rgba(255,255,255,0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ fontSize: '1.2rem', color: 'var(--cyber-blue)', margin: 0 }}>Threat Analysis Report</h2>
              <span className="close-modal" onClick={() => setSelectedScan(null)} style={{ cursor: 'pointer', fontSize: '1.5rem', color: 'rgba(255,255,255,0.5)' }}>&times;</span>
            </div>
            <div className="modal-body" style={{ padding: '2rem' }}>
              <div className="detail-row" style={{ marginBottom: '1rem', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '1rem' }}>
                <span className="detail-label" style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', marginBottom: '0.3rem', display: 'block' }}>Scanned URL</span>
                <div className="detail-value" style={{ color: 'var(--cyber-blue)' }}>{selectedScan.url}</div>
              </div>
              <div className="detail-row" style={{ marginBottom: '1rem', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '1rem' }}>
                <span className="detail-label" style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', marginBottom: '0.3rem', display: 'block' }}>Risk Context</span>
                <span className={`ti-pill ${selectedScan.score >= 80 ? 'safe' : selectedScan.score >= 50 ? 'warning' : 'danger'}`}>
                   {selectedScan.riskLabel} ({selectedScan.score}%)
                </span>
              </div>
              <div>
                <span className="detail-label" style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', marginBottom: '0.3rem', display: 'block' }}>Risk Factors Detected</span>
                <ul className="risk-list-detail" style={{ listStyle: 'none', padding: 0 }}>
                  {selectedScan.risks.map((r, i) => (
                    <li key={i} style={{ background: 'rgba(255, 75, 43, 0.1)', borderLeft: '3px solid var(--cyber-red)', padding: '0.5rem', marginBottom: '0.5rem', fontSize: '0.9rem' }}>{r}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
      
      <style jsx>{`
        .view-details-btn {
          background: transparent;
          border: none;
          color: var(--cyber-blue);
          cursor: pointer;
          text-decoration: underline;
          font-family: inherit;
          font-size: 0.8rem;
          transition: color 0.3s;
        }
        .view-details-btn:hover {
          color: #fff;
          text-shadow: 0 0 5px var(--cyber-blue);
        }
        .bar-safe { background: var(--cyber-green); box-shadow: 0 0 10px var(--cyber-green); transition: height 1s ease; }
        .bar-danger { background: var(--cyber-red); box-shadow: 0 0 10px var(--cyber-red); transition: height 1s ease; }
      `}</style>
    </main>
  );
}
