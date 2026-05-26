"use client";

import { useEffect } from "react";
import { motion, useMotionValue, useTransform, animate } from "framer-motion";

interface ScoreRingProps {
  score: number; // 0-100
}

function getColor(score: number): string {
  if (score < 30) return "#10b981"; // safe green
  if (score < 60) return "#f59e0b"; // warning amber
  return "#ef4444"; // danger red
}

const SIZE = 120;
const STROKE = 8;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreRing({ score }: ScoreRingProps) {
  const clampedScore = Math.max(0, Math.min(100, score));
  const color = getColor(clampedScore);

  const progress = useMotionValue(0);
  const dashOffset = useTransform(
    progress,
    [0, 100],
    [CIRCUMFERENCE, CIRCUMFERENCE - (CIRCUMFERENCE * clampedScore) / 100]
  );

  const scoreMotion = useMotionValue(0);

  useEffect(() => {
    const controls = animate(progress, clampedScore, {
      duration: 1.2,
      ease: "easeOut",
    });
    animate(scoreMotion, clampedScore, { duration: 1.2, ease: "easeOut" });
    return controls.stop;
  }, [clampedScore, progress, scoreMotion]);

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ width: SIZE, height: SIZE }}>
        <svg width={SIZE} height={SIZE} className="rotate-[-90deg]">
          {/* Track */}
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth={STROKE}
          />
          {/* Animated arc */}
          <motion.circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth={STROKE}
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            style={{ strokeDashoffset: dashOffset }}
          />
        </svg>

        {/* Center score text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center rotate-0">
          <motion.span
            className="text-2xl font-bold text-white leading-none"
            style={{ color }}
          >
            {Math.round(clampedScore)}
          </motion.span>
        </div>
      </div>
      <span className="text-xs text-slate-500 font-medium tracking-wide">
        Risk Score
      </span>
    </div>
  );
}
