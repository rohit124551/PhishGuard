import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0a0a0f",
        surface: "#12121a",
        border: "rgba(255,255,255,0.08)",
        purple: {
          accent: "#7c3aed",
          light: "#a855f7",
          dark: "#5b21b6",
        },
        safe: "#10b981",
        warning: "#f59e0b",
        danger: "#ef4444",
      },
      fontFamily: {
        inter: ["var(--font-inter)", "sans-serif"],
      },
      animation: {
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
        "fade-in": "fade-in 0.5s ease-out forwards",
        "spin-slow": "spin 3s linear infinite",
      },
      keyframes: {
        "pulse-glow": {
          "0%, 100%": { boxShadow: "0 0 8px 2px rgba(239,68,68,0.4)" },
          "50%": { boxShadow: "0 0 20px 6px rgba(239,68,68,0.7)" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      backgroundImage: {
        "dot-grid":
          "radial-gradient(rgba(124,58,237,0.15) 1px, transparent 1px)",
        "purple-gradient": "linear-gradient(135deg, #7c3aed, #ec4899)",
      },
      backgroundSize: {
        "dot-24": "24px 24px",
      },
    },
  },
  plugins: [],
};

export default config;
