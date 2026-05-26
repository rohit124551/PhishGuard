"use client";

import { Tag } from "lucide-react";

interface ExampleChipsProps {
  onSelect: (url: string) => void;
  disabled?: boolean;
}

const examples = [
  { label: "google.com", url: "https://google.com" },
  { label: "paypa1-login-verify.xyz", url: "http://paypa1-login-verify.xyz" },
  { label: "amazon-account-update.net", url: "http://amazon-account-update.net" },
];

export function ExampleChips({ onSelect, disabled }: ExampleChipsProps) {
  return (
    <div className="flex flex-wrap justify-center gap-2 mt-3">
      <span className="text-xs text-slate-500 self-center mr-1">Try:</span>
      {examples.map(({ label, url }) => (
        <button
          key={label}
          onClick={() => !disabled && onSelect(url)}
          disabled={disabled}
          className={`
            chip
            inline-flex items-center gap-1.5
            px-3 py-1.5 rounded-full text-xs font-medium
            bg-white/5 border border-white/10
            text-slate-300
            disabled:opacity-40 disabled:cursor-not-allowed
            transition-all
          `}
        >
          <Tag className="w-3 h-3 text-purple-400" />
          {label}
        </button>
      ))}
    </div>
  );
}
