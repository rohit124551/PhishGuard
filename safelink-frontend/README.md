# SafeLink — URL Safety Scanner Frontend

> **Know before you click.** A Next.js 14 + TypeScript frontend for the PhishGuard phishing URL detection system.

## Tech Stack

| Layer | Library |
|---|---|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript (strict) |
| Styling | Tailwind CSS |
| Animations | Framer Motion |
| Icons | Lucide React |

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Start the FastAPI backend
Make sure your Python backend is running on `http://localhost:8000`:
```bash
cd ../phishing-detector/backend
uvicorn main:app --reload
```

### 3. Run the dev server
```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## File Structure

```
safelink-frontend/
├── app/
│   ├── layout.tsx          # Root layout, dark theme, Inter font
│   ├── page.tsx            # Main scan page
│   └── globals.css         # Tailwind + custom CSS variables
├── components/
│   ├── URLInput.tsx        # Input field + scan button
│   ├── ResultCard.tsx      # Full result display (glassmorphism)
│   ├── CheckRow.tsx        # Individual check result row
│   ├── ScoreRing.tsx       # Animated SVG circular score
│   ├── VerdictBadge.tsx    # SAFE / SUSPICIOUS / DANGEROUS badge
│   └── ExampleChips.tsx    # Clickable example URL pills
├── types/
│   └── scan.ts             # All TypeScript interfaces
├── lib/
│   └── api.ts              # API client (POST /analyze, 10s timeout)
└── hooks/
    └── useScan.ts          # Scan state management hook
```

## API Contract

The frontend POSTs to `http://localhost:8000/analyze`:

```json
// Request
{ "url": "https://example.com" }

// Response
{
  "url": "https://example.com",
  "total_score": 15,
  "verdict": "safe",
  "checks": [
    { "name": "SSL Check", "score": 0, "status": "safe", "reason": "Valid HTTPS certificate" }
  ],
  "scanned_at": "2024-01-01T12:00:00Z"
}
```

## Design System

| Token | Value |
|---|---|
| Background | `#0a0a0f` |
| Surface | `#12121a` |
| Purple accent | `#7c3aed` |
| Safe green | `#10b981` |
| Warning amber | `#f59e0b` |
| Danger red | `#ef4444` |
