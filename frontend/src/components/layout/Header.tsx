import React from 'react';
import { ShieldCheck, Lock, Cpu } from 'lucide-react';

interface Props {
  airGapped?: boolean;
}

export const Header: React.FC<Props> = ({ airGapped = true }) => {
  return (
    <header className="bg-[#0A192F] text-white border-b border-slate-800 h-16 px-5 flex items-center justify-between sticky top-0 z-30 shadow-sm">
      {/* Institutional Context & TRINETRA Wordmark */}
      <div className="flex items-center gap-3.5">
        <div className="w-8 h-8 bg-blue-700 text-white flex items-center justify-center rounded border border-blue-500 shadow-xs shrink-0">
          <ShieldCheck className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="text-[9px] font-bold tracking-wider uppercase text-slate-400 leading-tight">
            NATIONAL TECHNICAL RESEARCH ORGANISATION <span className="text-slate-500 font-normal">· Government of India</span>
          </div>
          <div className="flex items-center gap-2.5 mt-0.5">
            <span className="font-extrabold text-base tracking-wider text-white leading-none">
              TRINETRA
            </span>
            <span className="text-[11px] text-slate-300 font-medium hidden md:inline leading-none">
              Sovereign IPsec Security Intelligence & Assessment Platform
            </span>
            <span className="text-[9.5px] font-mono px-2 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-700/60 hidden xl:inline leading-none">
              SIH 2026 · Problem Statement SIH26160 · Team Omega Coders
            </span>
          </div>
        </div>
      </div>

      {/* Sovereign Air-Gapped Status Bar */}
      <div className="flex items-center gap-3">
        {/* Engine Status */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-900/80 rounded border border-slate-700 text-xs text-slate-300">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-mono text-[11px]">ENGINE ONLINE</span>
        </div>

        {/* Air-Gapped Mode */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-blue-950/80 rounded border border-blue-800 text-xs text-blue-300 font-medium">
          <Lock className="w-3.5 h-3.5 text-blue-400" />
          <span>AIR-GAPPED / LOCAL</span>
        </div>

        {/* Rule Pack Tag */}
        <div className="hidden lg:flex items-center gap-1 text-slate-400 text-xs font-mono border-l border-slate-700 pl-3">
          <Cpu className="w-3.5 h-3.5 text-slate-400" />
          <span>v2026.03.1</span>
        </div>
      </div>

      {/* Subtle institutional Indian tricolour accent line at bottom of header */}
      <div className="absolute bottom-0 left-0 right-0 h-[2px] flex">
        <div className="w-1/3 bg-[#FF9933]" />
        <div className="w-1/3 bg-[#FFFFFF]" />
        <div className="w-1/3 bg-[#138808]" />
      </div>
    </header>
  );
};
