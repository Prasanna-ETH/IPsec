import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  Network,
  ShieldAlert,
  Activity,
  FileSearch,
  GitCompare,
  FileText,
  BookOpen,
  Server
} from 'lucide-react';

export type NavRoute =
  | 'overview'
  | 'captures'
  | 'tunnels'
  | 'findings'
  | 'intelligence'
  | 'evidence'
  | 'compare'
  | 'reports'
  | 'standards'
  | 'system';

interface Props {
  currentRoute: NavRoute;
  onRouteChange: (route: NavRoute) => void;
  openFindingsCount?: number;
}

export const Sidebar: React.FC<Props> = ({
  currentRoute,
  onRouteChange,
  openFindingsCount = 0
}) => {
  const navItems: Array<{ id: NavRoute; label: string; icon: React.ReactNode; badge?: number }> = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'captures', label: 'Capture Center', icon: <UploadCloud className="w-4 h-4" /> },
    { id: 'tunnels', label: 'Tunnels', icon: <Network className="w-4 h-4" /> },
    {
      id: 'findings',
      label: 'Security Findings',
      icon: <ShieldAlert className="w-4 h-4" />,
      badge: openFindingsCount > 0 ? openFindingsCount : undefined
    },
    { id: 'intelligence', label: 'Traffic Intelligence', icon: <Activity className="w-4 h-4" /> },
    { id: 'evidence', label: 'Evidence Explorer', icon: <FileSearch className="w-4 h-4" /> },
    { id: 'compare', label: 'Compare Captures', icon: <GitCompare className="w-4 h-4" /> },
    { id: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
    { id: 'standards', label: 'Standards & Rules', icon: <BookOpen className="w-4 h-4" /> },
    { id: 'system', label: 'System Status', icon: <Server className="w-4 h-4" /> },
  ];

  return (
    <aside className="w-60 bg-[#0F2544] text-slate-300 flex flex-col justify-between border-r border-slate-800 shrink-0 select-none h-full overflow-y-auto">
      {/* Navigation list */}
      <div className="py-3 px-2">
        <div className="px-3 pb-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">
          Analyst Console
        </div>
        <nav className="space-y-0.5">
          {navItems.map((item) => {
            const isActive = currentRoute === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onRouteChange(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600 text-white font-semibold shadow-xs'
                    : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <span className={isActive ? 'text-white' : 'text-slate-400'}>{item.icon}</span>
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold ${
                      isActive ? 'bg-red-500 text-white' : 'bg-red-900/80 text-red-200 border border-red-700/60'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer info box */}
      <div className="p-3 border-t border-slate-800 bg-[#0A192F]/60 text-[11px] text-slate-400 space-y-1">
        <div className="flex justify-between items-center font-mono text-[10px]">
          <span className="font-semibold text-slate-300">SIH 2026 / SIH26160</span>
          <span className="text-emerald-400">PASV-v1.0</span>
        </div>
        <div className="text-[10px] text-blue-400/90 font-medium">
          Team Omega Coders
        </div>
        <div className="text-[9.5px] text-slate-500">
          No payload decryption required.
        </div>
      </div>
    </aside>
  );
};
