import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Tunnel, FlowWindow, CaptureSummary } from '../types';
import { VisibilityBadge } from '../components/common/VisibilityBadge';
import {
  Activity,
  Cpu,
  BarChart3,
  Layers,
  HelpCircle,
  AlertTriangle,
  Info,
  TrendingUp
} from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const TrafficIntelligencePage: React.FC<Props> = ({ onNavigate }) => {
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [selectedTunnelId, setSelectedTunnelId] = useState<string>('');
  const [flowWindows, setFlowWindows] = useState<FlowWindow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadInitial();
  }, []);

  const loadInitial = async () => {
    try {
      setLoading(true);
      const caps = await api.getCaptures();
      setCaptures(caps);
      if (caps.length > 0) {
        setSelectedCaptureId(caps[0].id);
        const tList = await api.getCaptureTunnels(caps[0].id);
        setTunnels(tList);
        if (tList.length > 0) {
          setSelectedTunnelId(tList[0].id);
          const windows = await api.getTunnelWindows(tList[0].id);
          setFlowWindows(windows);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleTunnelChange = async (tId: string) => {
    setSelectedTunnelId(tId);
    try {
      const windows = await api.getTunnelWindows(tId);
      setFlowWindows(windows);
    } catch (e) {
      console.error(e);
    }
  };

  const latestWindow = flowWindows[0] || null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">
            Encrypted Traffic Intelligence & ML Behaviour
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Statistical flow dynamics and explainable XGBoost behavioral inference derived strictly from ESP metadata.
          </p>
        </div>

        {/* Tunnel Selector */}
        {tunnels.length > 0 && (
          <select
            value={selectedTunnelId}
            onChange={(e) => handleTunnelChange(e.target.value)}
            className="font-bold text-slate-800 bg-white border border-slate-300 rounded px-3 py-1.5 text-xs shadow-xs focus:ring-1 focus:ring-blue-600"
          >
            {tunnels.map((t) => (
              <option key={t.id} value={t.id}>
                Tunnel: {t.tunnel_key} ({t.packet_count} pkts)
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Primary ML Classification Card */}
      <div className="bg-white border border-slate-200 rounded p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-4 border-b border-slate-200 gap-2">
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
              Encrypted Flow Behavioral Classification
            </div>
            <div className="text-xl font-extrabold font-mono text-blue-950 mt-1 flex items-center gap-2">
              <Cpu className="w-5 h-5 text-blue-700" />
              {latestWindow?.predicted_class || 'Awaiting Flow Samples'}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <VisibilityBadge
              type="INFERRED"
              confidence={latestWindow?.class_confidence ?? 0.8}
            />
            <div className="text-right font-mono text-xs text-slate-500 border-l border-slate-200 pl-3">
              Confidence: <strong className="text-slate-800">{Math.round((latestWindow?.class_confidence ?? 0.8) * 100)}%</strong>
            </div>
          </div>
        </div>

        {/* SHAP / Feature Contribution Breakdown */}
        <div className="mt-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-1.5">
            <TrendingUp className="w-4 h-4 text-slate-600" />
            Explainability: Contributing Feature Weights
          </h4>

          {latestWindow?.shap_features && Object.keys(latestWindow.shap_features).length > 0 ? (
            <div className="space-y-2.5">
              {Object.entries(latestWindow.shap_features).map(([featName, weight], idx) => {
                const pct = Math.round(weight * 100);
                return (
                  <div key={idx} className="text-xs">
                    <div className="flex justify-between text-slate-700 font-medium mb-1">
                      <span>{featName}</span>
                      <span className="font-mono font-bold text-blue-900">+{pct}% contribution</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-xs text-slate-500 font-mono py-2">
              Feature contributions computed across sliding temporal windows.
            </div>
          )}
        </div>

        {/* Strict Visibility Caution Banner */}
        <div className="mt-6 p-3 bg-slate-50 border border-slate-200 rounded text-[11px] text-slate-600 flex items-center gap-2">
          <Info className="w-4 h-4 text-blue-600 shrink-0" />
          <span>
            <strong>Analyst Note:</strong> Flow classifications represent external statistical dynamics (e.g. bulk transfer vs interactive)
            and do NOT inspect or claim access to encrypted application-layer protocols or inner packet payloads.
          </span>
        </div>
      </div>

      {/* Flow Windows Table */}
      <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
        <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 font-bold text-xs uppercase text-slate-700">
          Sliding Flow Feature Windows
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Window #</th>
                <th className="py-2.5 px-4">Time Span</th>
                <th className="py-2.5 px-4">Packets</th>
                <th className="py-2.5 px-4">Mean Size</th>
                <th className="py-2.5 px-4">Mean IAT</th>
                <th className="py-2.5 px-4">Direction Skew</th>
                <th className="py-2.5 px-4">Bursts</th>
                <th className="py-2.5 px-4">Inferred Class</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
              {flowWindows.map((w) => (
                <tr key={w.id} className="hover:bg-slate-50">
                  <td className="py-2.5 px-4 font-bold">W-{w.window_index + 1}</td>
                  <td className="py-2.5 px-4 text-slate-600">
                    +{w.start_time.toFixed(1)}s → +{w.end_time.toFixed(1)}s
                  </td>
                  <td className="py-2.5 px-4 font-bold text-slate-900">{w.packet_count}</td>
                  <td className="py-2.5 px-4">{w.mean_size} B</td>
                  <td className="py-2.5 px-4">{(w.mean_iat * 1000).toFixed(1)} ms</td>
                  <td className="py-2.5 px-4 text-slate-700">
                    {Math.round(w.upstream_ratio * 100)}% / {Math.round((1 - w.upstream_ratio) * 100)}%
                  </td>
                  <td className="py-2.5 px-4">{w.burst_count}</td>
                  <td className="py-2.5 px-4 font-sans font-semibold text-blue-900">
                    {w.predicted_class} ({Math.round(w.class_confidence * 100)}%)
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
