"use client";

import { motion } from "framer-motion";
import { CheckResult } from "@/types/scan";
import { Check, AlertTriangle, XCircle } from "lucide-react";

interface CheckRowProps {
  check: CheckResult;
  index: number;
}

const statusConfig = {
  safe: {
    borderColor: "border-l-emerald-500",
    iconColor: "text-emerald-400",
    Icon: Check,
    bg: "bg-emerald-500/10",
  },
  warning: {
    borderColor: "border-l-amber-500",
    iconColor: "text-amber-400",
    Icon: AlertTriangle,
    bg: "bg-amber-500/10",
  },
  danger: {
    borderColor: "border-l-red-500",
    iconColor: "text-red-400",
    Icon: XCircle,
    bg: "bg-red-500/10",
  },
};

export function CheckRow({ check, index }: CheckRowProps) {
  const config = statusConfig[check.status];
  const { Icon } = config;

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1, duration: 0.35, ease: "easeOut" }}
      className={`
        group flex items-start justify-between gap-4
        border-l-[3px] ${config.borderColor}
        rounded-r-lg px-4 py-3
        hover:bg-white/[0.03] transition-colors duration-200
        cursor-default
      `}
    >
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-slate-100 truncate">{check.name}</p>
        <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{check.reason}</p>
      </div>

      <div className={`shrink-0 p-1.5 rounded-md ${config.bg}`}>
        <Icon className={`w-4 h-4 ${config.iconColor}`} strokeWidth={2.5} />
      </div>
    </motion.div>
  );
}
