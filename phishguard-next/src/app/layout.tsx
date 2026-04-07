import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard | Advanced URL Scanner",
  description: "Real-time heuristic analysis for phishing threat detection.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link 
          rel="stylesheet" 
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
        />
      </head>
      <body>
        {/* Decorative Orbs */}
        <div className="orb orb-1"></div>
        <div className="orb orb-2"></div>
        
        {children}

        <footer style={{ textAlign: 'center', padding: '2rem', fontSize: '0.9rem', color: 'rgba(255, 255, 255, 0.4)' }}>
          &copy; {new Date().getFullYear()} PhishGuard. All rights reserved.
        </footer>
      </body>
    </html>
  );
}
