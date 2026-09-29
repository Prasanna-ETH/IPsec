import React from 'react';
import { Severity } from '../../types';

interface Props {
  score: number;
  level: Severity | string;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskGauge: React.FC<Props> = ({ score, level, size = 'md' }) => {
  const rounded = Math.round(score);

  const getColor = (s: number) => {
    if (s >= 75) return { text: 'text-red-600', bg: 'bg-red-500', border: 'border-red-500', barBg: 'bg-red-100' };
    if (s >= 50) return { text: 'text-orange-600', bg: 'bg-orange-500', border: 'border-orange-500', barBg: 'bg-orange-100' };
    if (s >= 25) return { text: 'text-amber-600', bg: 'bg-amber-500', border: 'border-amber-500', barBg: 'bg-amber-100' };
    if (s > 0) return { text: 'text-blue-600', bg: 'bg-blue-500', border: 'border-blue-500', barBg: 'bg-blue-100' };
    return { text: 'text-emerald-600', bg: 'bg-emerald-500', border: 'border-emerald-500', barBg: 'bg-emerald-100' };
  };

  const theme = getColor(score);

  if (size === 'sm') {
    return (
      <div className="flex items-center gap-2">
        <div className="w-16 h-2 bg-slate-200 rounded-full overflow-hidden">
          <div className={`h-full ${theme.bg}`} style={{ width: `${Math.min(100, Math.max(5, score))}%` }} />
        </div>
        <span className={`font-mono text-xs font-bold ${theme.text}`}>{rounded}</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-4 bg-white border border-slate-200 rounded p-4">
      <div className="text-center">
        <div className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-0.5">Risk Score</div>
        <div className={`text-3xl font-extrabold font-mono ${theme.text}`}>
          {rounded} <span className="text-sm font-normal text-slate-400">/ 100</span>
        </div>
      </div>
      <div className="flex-1 pl-3 border-l border-slate-200">
        <div className="flex justify-between items-center mb-1">
          <span className="text-xs font-semibold text-slate-700">Posture: <span className={theme.text}>{level}</span></span>
          <span className="text-xs text-slate-500 font-mono">{rounded}%</span>
        </div>
        <div className="w-full h-2.5 bg-slate-100 border border-slate-200 rounded-full overflow-hidden">
          <div
            className={`h-full ${theme.bg} transition-all duration-300`}
            style={{ width: `${Math.min(100, Math.max(3, score))}%` }}
          />
        </div>
      </div>
    </div>
  );
};
