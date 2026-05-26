import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "PhishGuard — Real-Time Phishing URL Detection System",
  description:
    "Protect yourself from phishing attacks. Scan any URL instantly to detect malicious links and secure your online identity.",
  keywords: ["phishing", "url scanner", "link safety", "safe browsing"],
  openGraph: {
    title: "PhishGuard — Know Before You Click",
    description: "Instant phishing and malware detection for any URL.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable} suppressHydrationWarning>
      <body className="antialiased">{children}</body>
    </html>
  );
}
