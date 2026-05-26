"use client";

import { motion } from "framer-motion";
import { Shield, AlertTriangle, XCircle } from "lucide-react";

type Verdict = "safe" | "suspicious" | "dangerous";

interface VerdictBadgeProps {
  verdict: Verdict;
}

const config: Record<
  Verdict,
  { label: string; className: string; Icon: typeof Shield; extra?: string }
> = {
  safe: {
    label: "SAFE",
    Icon: Shield,
    className:
      "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 safe-glow",
  },
  suspicious: {
    label: "SUSPICIOUS",
    Icon: AlertTriangle,
    className:
      "bg-amber-500/20 text-amber-300 border border-amber-500/40",
  },
  dangerous: {
    label: "DANGEROUS",
    Icon: XCircle,
    className:
      "bg-red-500/20 text-red-300 border border-red-500/40 danger-pulse",
  },
};

export function VerdictBadge({ verdict }: VerdictBadgeProps) {
  const { label, Icon, className } = config[verdict];

  return (
    <motion.div
      initial={{ scale: 0.85, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: "spring", stiffness: 260, damping: 20 }}
      className={`
        inline-flex items-center gap-2.5
        px-5 py-2.5 rounded-full
        text-sm font-bold tracking-widest uppercase
        ${className}
      `}
    >
      <Icon className="w-4 h-4" strokeWidth={2.5} />
      {label}
    </motion.div>
  );
}
