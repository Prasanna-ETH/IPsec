import React from 'react';
import { ShieldCheck, Server, Lock, Cpu } from 'lucide-react';

interface Props {
  airGapped?: boolean;
}

export const Header: React.FC<Props> = ({ airGapped = true }) => {
  return (
    <header className="bg-[#0A192F] text-white border-b border-slate-800 h-14 px-5 flex items-center justify-between sticky top-0 z-30 shadow-sm">
      {/* Wordmark and Subtitle */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 bg-blue-700 text-white font-bold flex items-center justify-center rounded text-sm tracking-wider border border-blue-500">
            Ω
          </div>
          <div>
            <div className="font-extrabold text-base tracking-wider text-slate-100 flex items-center gap-2">
              OMEGA
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-900/80 text-blue-300 border border-blue-700/60 uppercase">
                SIH26160
              </span>
            </div>
            <div className="text-[11px] text-slate-400 font-medium tracking-tight -mt-0.5">
              Sovereign IPsec Security Intelligence & Assessment Platform
            </div>
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
