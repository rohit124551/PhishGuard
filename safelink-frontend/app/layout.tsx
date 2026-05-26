import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "SafeLink — Free URL Safety Scanner",
  description:
    "Instantly check if any URL is safe, suspicious, or dangerous before you click. Powered by multi-factor phishing detection.",
  keywords: ["phishing", "url scanner", "link safety", "safe browsing"],
  openGraph: {
    title: "SafeLink — Know Before You Click",
    description: "Free URL safety scanner powered by AI phishing detection.",
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
