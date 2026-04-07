# PhishGuard | Modern URL Scanner

**PhishGuard** is a robust web application built with **Next.js** designed to help users identify potential phishing threats in real-time. By utilizing advanced heuristic analysis and server-side intelligence, PhishGuard provides a comprehensive safety score and detailed risk assessment for any URL.

## 🚀 Key Features

- **Heuristic Analysis**: Detects IP usage, typosquatting, suspicious TLDs, and extensive subdomains.
- **Homoglyph Detection**: Identifies characters that look identical to standard Latin characters (e.g., Cyrillic 'a' vs Latin 'a').
- **Modern Dashboard**: Track your scan history and view risk seat distribution in a high-performance interactive interface.
- **Next.js Power**: Leverages server-side rendering and API routes for enhanced security and performance.
- **Glassmorphism UI**: A premium, responsive design that ensures a stunning user experience on all devices.

## 🛠️ Getting Started

To run the application locally:

1.  **Navigate to the project folder:**
    ```bash
    cd phishguard-next
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Run the development server:**
    ```bash
    npm run dev
    ```

4.  **Open the App:**
    Visit [http://localhost:3000](http://localhost:3000) in your browser.

## 🏗️ Technology Stack

- **Framework**: Next.js 16 (App Router)
- **Styling**: Vanilla CSS with modern Glassmorphism utilities
- **State Management**: React Hooks (useState, useEffect)
- **Icons**: Font Awesome 6.4.0
- **Typography**: Google Fonts (Outfit)

## 🛡️ Heuristic Engine

The core analysis logic is located in `src/lib/scanner.ts`. It performs several checks, including:
- **IP Check**: Detects if a URL uses a raw IP address instead of a domain name.
- **Entropy Analysis**: Identifies high-randomness hostnames often used in DGA (Domain Generation Algorithms).
- **Keyword Check**: Flags sensitive keywords like "login", "bank", or "verify" in suspicious contexts.
- **TLD Risk**: Warns about Top-Level Domains frequently associated with malicious activity.

---
© 2025 Rohit Kumar Ranjan. All rights reserved.
