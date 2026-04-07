"use client";

import { useEffect, useState } from "react";

export default function NetworkStatus() {
  const [ip, setIp] = useState<string | null>(null);

  useEffect(() => {
    fetch("https://ipapi.co/json/")
      .then((response) => response.json())
      .then((data) => setIp(data.ip))
      .catch(() => setIp("Hidden"));
  }, []);

  return (
    <div className="network-badge animate-fade-in" style={{ 
      display: 'flex', 
      alignItems: 'center', 
      gap: '8px', 
      padding: '0.4rem 1rem', 
      background: 'rgba(255, 255, 255, 0.05)', 
      borderRadius: '20px', 
      fontSize: '0.75rem', 
      border: '1px solid rgba(255, 255, 255, 0.1)',
      color: 'rgba(255, 255, 255, 0.6)',
    }}>
      <div className="pulse-dot"></div>
      <span>{ip ? ip : "Detecting..."}</span>

      <style jsx>{`
        .pulse-dot {
          width: 6px;
          height: 6px;
          background: var(--accent-color);
          border-radius: 50%;
          box-shadow: 0 0 5px var(--accent-color);
          animation: pulse 2s infinite;
        }

        @keyframes pulse {
          0% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.5); opacity: 0.5; }
          100% { transform: scale(1); opacity: 1; }
        }
      `}</style>
    </div>
  );
}
