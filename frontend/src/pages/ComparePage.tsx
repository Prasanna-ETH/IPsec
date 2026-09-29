import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { CaptureSummary, ComparisonResponse } from '../types';
import { GitCompare, CheckCircle2, ArrowRight, ShieldCheck, AlertCircle, RotateCcw } from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const ComparePage: React.FC<Props> = ({ onNavigate }) => {
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [baselineId, setBaselineId] = useState<string>('');
  const [remediationId, setRemediationId] = useState<string>('');
  const [comparison, setComparison] = useState<ComparisonResponse | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadCaptures();
  }, []);

  const loadCaptures = async () => {
    try {
      const caps = await api.getCaptures();
      setCaptures(caps);
      if (caps.length >= 2) {
        setBaselineId(caps[1].id);
        setRemediationId(caps[0].id);
      } else if (caps.length === 1) {
        setBaselineId(caps[0].id);
        setRemediationId(caps[0].id);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleRunComparison = async () => {
    if (!baselineId || !remediationId) return;
    try {
      setLoading(true);
      const res = await api.compareCaptures(baselineId, remediationId);
      setComparison(res);
    } catch (e: any) {
      alert(`Comparison failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">
          Capture Comparison & Remediation Verification
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Verify whether configuration hardening improved observable cryptographic posture between baseline and post-remediation captures.
        </p>
      </div>

      {/* Capture Selectors & Action Card */}
      <div className="bg-white border border-slate-200 rounded p-6 shadow-xs">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
          {/* Baseline Capture */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-600 block">
              Baseline Network Capture (Pre-Hardening)
            </label>
            <select
              value={baselineId}
              onChange={(e) => setBaselineId(e.target.value)}
              className="w-full bg-slate-50 border border-slate-300 rounded px-3 py-2 text-xs font-bold text-slate-900 focus:outline-none focus:ring-1 focus:ring-blue-600"
            >
              {captures.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} (Risk: {c.overall_risk_score}/100 • {c.packet_count} pkts)
                </option>
              ))}
            </select>
          </div>

          {/* Remediation Capture */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-600 block">
              Remediation Network Capture (Post-Hardening)
            </label>
            <select
              value={remediationId}
              onChange={(e) => setRemediationId(e.target.value)}
              className="w-full bg-slate-50 border border-slate-300 rounded px-3 py-2 text-xs font-bold text-slate-900 focus:outline-none focus:ring-1 focus:ring-blue-600"
            >
              {captures.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} (Risk: {c.overall_risk_score}/100 • {c.packet_count} pkts)
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-5 pt-4 border-t border-slate-200 flex justify-end">
          <button
            onClick={handleRunComparison}
            disabled={loading || !baselineId || !remediationId}
            className="px-5 py-2 bg-blue-700 hover:bg-blue-800 disabled:bg-slate-400 text-white rounded text-xs font-bold flex items-center gap-2 shadow-xs"
          >
            <GitCompare className="w-4 h-4" />
            {loading ? 'Comparing Captures...' : 'RUN REMEDIATION COMPARISON'}
          </button>
        </div>
      </div>

      {/* Comparison Results Card */}
      {comparison && (
        <div className="space-y-6">
          {/* Posture Score Delta Banner */}
          <div className="bg-slate-900 text-white p-5 rounded border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div>
              <div className="text-[10px] font-mono text-slate-400 uppercase">Verification Summary</div>
              <div className="text-base font-bold text-slate-100 mt-0.5">{comparison.summary}</div>
            </div>

            <div className="flex items-center gap-6 font-mono">
              <div className="text-center">
                <div className="text-[10px] text-slate-400">BASELINE RISK</div>
                <div className="text-xl font-extrabold text-red-400">{comparison.baseline_risk_score}</div>
              </div>

              <div className="text-slate-500 font-bold text-lg">→</div>

              <div className="text-center">
                <div className="text-[10px] text-slate-400">POST-REMED RISK</div>
                <div className="text-xl font-extrabold text-emerald-400">{comparison.remediation_risk_score}</div>
              </div>

              <div className="text-center border-l border-slate-700 pl-4">
                <div className="text-[10px] text-slate-400">DELTA</div>
                <div className={`text-xl font-extrabold ${comparison.risk_delta < 0 ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {comparison.risk_delta > 0 ? `+${comparison.risk_delta}` : comparison.risk_delta} pts
                </div>
              </div>
            </div>
          </div>

          {/* Audit Diff Table */}
          <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 font-bold text-xs uppercase text-slate-700 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              Cryptographic Control Transformation Matrix
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                    <th className="py-2.5 px-4">Control Description</th>
                    <th className="py-2.5 px-4">Baseline (Before)</th>
                    <th className="py-2.5 px-4">Remediation (After)</th>
                    <th className="py-2.5 px-4">Change Status</th>
                    <th className="py-2.5 px-4">Standards Rationale</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-[12px]">
                  {comparison.diff_table.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-50">
                      <td className="py-3 px-4 font-bold text-slate-900">{item.control}</td>
                      <td className="py-3 px-4 font-mono text-red-800 bg-red-50/40">{item.baseline_value}</td>
                      <td className="py-3 px-4 font-mono text-emerald-800 bg-emerald-50/40 font-bold">
                        {item.remediation_value}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold ${
                            item.change_status === 'IMPROVED'
                              ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                              : item.change_status === 'DEGRADED'
                              ? 'bg-red-100 text-red-800 border border-red-300'
                              : 'bg-slate-100 text-slate-700 border border-slate-300'
                          }`}
                        >
                          {item.change_status === 'IMPROVED' && <CheckCircle2 className="w-3 h-3" />}
                          {item.change_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-600 text-[11px]">
                        <div>{item.rationale}</div>
                        {item.standards_rule && (
                          <div className="font-mono text-slate-400 mt-0.5">{item.standards_rule}</div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
