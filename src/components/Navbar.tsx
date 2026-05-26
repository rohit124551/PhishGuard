"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export default function Navbar() {
  const pathname = usePathname();

  return (
    <header className="glass" style={{ padding: '0.8rem 5%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '1rem', borderRadius: '12px' }}>
      <div className="logo-group" style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
        <div className="logo" style={{ fontSize: '1.8rem', fontWeight: 700, letterSpacing: '1px', background: 'linear-gradient(to right, var(--accent-color), #fff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          PhishGuard
        </div>
      </div>
      <nav className="nav-menu" style={{ display: 'flex', gap: '1rem' }}>
        <Link href="/">
          <button className={`nav-btn ${pathname === "/" ? "active" : ""}`}>
            Home
          </button>
        </Link>
        <Link href="/dashboard">
          <button className={`nav-btn ${pathname === "/dashboard" ? "active" : ""}`}>
            Dashboard
          </button>
        </Link>
      </nav>

      <style jsx>{`
        .nav-btn {
          background: transparent;
          border: none;
          color: rgba(255, 255, 255, 0.7);
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          padding: 0.5rem 1rem;
          position: relative;
          transition: all 0.3s ease;
        }
        .nav-btn:hover, .nav-btn.active {
          color: #fff;
          text-shadow: 0 0 10px rgba(0, 210, 255, 0.5);
        }
        .nav-btn::after {
          content: '';
          position: absolute;
          bottom: 0;
          left: 50%;
          width: 0;
          height: 2px;
          background: var(--accent-color);
          transition: all 0.3s ease;
          transform: translateX(-50%);
        }
        .nav-btn:hover::after, .nav-btn.active::after {
          width: 80%;
        }
      `}</style>
    </header>
  );
}
