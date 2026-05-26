"use client";

import { useEffect, useState } from "react";

export default function UserIdentity() {
  const [ip, setIp] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("https://api.ipify.org?format=json")
      .then((response) => response.json())
      .then((data) => {
        setIp(data.ip);
        setLoading(false);
      })
      .catch(() => {
        setIp("Hidden");
        setLoading(false);
      });
  }, []);

  return (
    <div className="stat-card glass-blue animate-fade-in" style={{ 
      position: 'relative', 
      borderLeft: '4px solid var(--accent-color)',
      background: 'rgba(10, 14, 23, 0.8)'
    }}>
      <div className="stat-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'rgba(255, 255, 255, 0.5)', marginBottom: '0.5rem' }}>
        <span>NETWORK IDENTITY</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
          <div className={`pulse-dot ${loading ? 'scanning' : 'active'}`}></div>
          <span style={{ fontSize: '0.7rem', color: loading ? 'var(--warning-color)' : 'var(--success-color)' }}>
            {loading ? 'DETECTING' : 'SECURE'}
          </span>
        </div>
      </div>

      <div className="stat-value" id="userIp" style={{ fontSize: '1.8rem', fontWeight: 700, margin: '0.5rem 0', color: 'var(--accent-color)' }}>
        {loading ? 'Detecting...' : ip ? `${ip}` : 'IP: Hidden'}
      </div>

      <style jsx>{`
        .pulse-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }
        .pulse-dot.active {
          background: var(--success-color);
          box-shadow: 0 0 10px var(--success-color);
          animation: pulse 2s infinite;
        }
        .pulse-dot.scanning {
          background: var(--warning-color);
          animation: blink 1s infinite;
        }
        @keyframes pulse {
          0% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.5); opacity: 0.5; }
          100% { transform: scale(1); opacity: 1; }
        }
        @keyframes blink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
      `}</style>
    </div>
  );
}
