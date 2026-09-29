import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { CaptureSummary, Tunnel, Finding, RiskAssessment } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { RiskGauge } from '../components/common/RiskGauge';
import {
  ShieldAlert,
  Network,
  Radio,
  FileCheck2,
  Lock,
  ArrowRight,
  UploadCloud,
  Layers,
  AlertTriangle,
  FileText
} from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const OverviewPage: React.FC<Props> = ({ onNavigate }) => {
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [selectedCapture, setSelectedCapture] = useState<CaptureSummary | null>(null);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [risk, setRisk] = useState<RiskAssessment | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const caps = await api.getCaptures();
      setCaptures(caps);

      if (caps.length > 0) {
        const latest = caps[0];
        setSelectedCapture(latest);
        const [tList, fList, rData] = await Promise.all([
          api.getCaptureTunnels(latest.id),
          api.getCaptureFindings(latest.id),
          api.getCaptureRisk(latest.id)
        ]);
        setTunnels(tList);
        setFindings(fList);
        setRisk(rData);
      }
    } catch (e) {
      console.error('Error loading overview data:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectCapture = async (capId: string) => {
    const found = captures.find((c) => c.id === capId);
    if (found) {
      setSelectedCapture(found);
      try {
        const [tList, fList, rData] = await Promise.all([
          api.getCaptureTunnels(found.id),
          api.getCaptureFindings(found.id),
          api.getCaptureRisk(found.id)
        ]);
        setTunnels(tList);
        setFindings(fList);
        setRisk(rData);
      } catch (e) {
        console.error(e);
      }
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 font-mono text-xs">
        LOADING ASSESSMENT DASHBOARD...
      </div>
    );
  }

  if (captures.length === 0) {
    return (
      <div className="bg-white border border-slate-200 rounded p-12 text-center max-w-xl mx-auto mt-12 shadow-xs">
        <UploadCloud className="w-12 h-12 text-slate-400 mx-auto mb-4" />
        <h2 className="text-lg font-bold text-slate-800 mb-2">No Network Capture Analyzed</h2>
        <p className="text-xs text-slate-500 mb-6 max-w-sm mx-auto">
          Upload a PCAP or PCAPNG network trace in the Capture Center to begin passive IPsec inspection and standards assessment.
        </p>
        <button
          onClick={() => onNavigate('captures')}
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-800 text-white rounded text-xs font-semibold shadow-xs"
        >
          <UploadCloud className="w-4 h-4" />
          GO TO CAPTURE CENTER
        </button>
      </div>
    );
  }

  // Calculate count metrics
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW').length;

  return (
    <div className="space-y-6">
      {/* Top Bar: Target Capture Selector and Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white p-4 rounded border border-slate-200">
        <div>
          <div className="text-xs uppercase font-semibold text-slate-500 tracking-wider">
            Active Target Capture
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <select
              value={selectedCapture?.id}
              onChange={(e) => handleSelectCapture(e.target.value)}
              className="font-bold text-slate-900 bg-slate-50 border border-slate-300 rounded px-2.5 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-blue-600"
            >
              {captures.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} ({c.packet_count} pkts • SHA256: {c.sha256.slice(0, 10)}...)
                </option>
              ))}
            </select>
            <span className="text-xs text-slate-500 font-mono">
              Status: <span className="text-emerald-700 font-bold">{selectedCapture?.status}</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigate('reports')}
            className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded text-xs font-medium border border-slate-300 flex items-center gap-1.5"
          >
            <FileText className="w-3.5 h-3.5 text-slate-500" />
            Generate Report
          </button>
          <button
            onClick={() => onNavigate('captures')}
            className="px-3 py-1.5 bg-blue-700 hover:bg-blue-800 text-white rounded text-xs font-semibold flex items-center gap-1.5"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            New Capture
          </button>
        </div>
      </div>

      {/* Row 1: KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Posture Score */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Overall Posture</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-extrabold font-mono text-slate-900">
              {risk?.overall_score ?? 0}
            </span>
            <span className="text-xs font-mono text-slate-400">/ 100</span>
          </div>
          <div className="mt-2">
            <SeverityBadge severity={risk?.risk_level ?? 'INFORMATIONAL'} />
          </div>
        </div>

        {/* Tunnels */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Tunnels Detected</div>
          <div className="mt-1 text-2xl font-extrabold font-mono text-slate-900">{tunnels.length}</div>
          <div className="mt-2 text-xs text-slate-500 flex items-center gap-1">
            <Network className="w-3.5 h-3.5 text-blue-600" />
            <span>Endpoint Pairings</span>
          </div>
        </div>

        {/* IKE Sessions */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">IKE Sessions</div>
          <div className="mt-1 text-2xl font-extrabold font-mono text-slate-900">
            {tunnels.reduce((acc, t) => acc + t.ike_sessions_count, 0)}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center gap-1">
            <Radio className="w-3.5 h-3.5 text-indigo-600" />
            <span>{selectedCapture?.ike_packet_count} IKE Frames</span>
          </div>
        </div>

        {/* ESP SAs */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">ESP SAs</div>
          <div className="mt-1 text-2xl font-extrabold font-mono text-slate-900">
            {tunnels.reduce((acc, t) => acc + t.esp_sas_count, 0)}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center gap-1">
            <Layers className="w-3.5 h-3.5 text-slate-600" />
            <span>{selectedCapture?.esp_packet_count} Encrypted ESP Frames</span>
          </div>
        </div>

        {/* Open Findings */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Open Findings</div>
          <div className="mt-1 text-2xl font-extrabold font-mono text-red-600">{findings.length}</div>
          <div className="mt-2 text-xs text-slate-500 flex items-center gap-1">
            <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
            <span>{criticalCount} Critical, {highCount} High</span>
          </div>
        </div>
      </div>

      {/* Row 2: Tunnel Security Overview Table */}
      <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <div className="font-bold text-slate-800 text-xs uppercase tracking-wider flex items-center gap-2">
            <Network className="w-4 h-4 text-slate-600" />
            Tunnel Security Overview
          </div>
          <button
            onClick={() => onNavigate('tunnels')}
            className="text-xs text-blue-700 hover:text-blue-800 font-semibold flex items-center gap-1"
          >
            Explore Tunnels <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Tunnel Key</th>
                <th className="py-2.5 px-4">Endpoint A</th>
                <th className="py-2.5 px-4">Endpoint B</th>
                <th className="py-2.5 px-4">IKE Version</th>
                <th className="py-2.5 px-4">Encapsulation</th>
                <th className="py-2.5 px-4">Risk Posture</th>
                <th className="py-2.5 px-4">Findings</th>
                <th className="py-2.5 px-4">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {tunnels.map((t) => (
                <tr key={t.id} className="hover:bg-slate-50 font-mono text-[12px]">
                  <td className="py-2.5 px-4 font-bold text-slate-800">{t.tunnel_key}</td>
                  <td className="py-2.5 px-4 text-slate-700">{t.endpoint_a}</td>
                  <td className="py-2.5 px-4 text-slate-700">{t.endpoint_b}</td>
                  <td className="py-2.5 px-4 text-slate-800">{t.ike_version || 'N/A'}</td>
                  <td className="py-2.5 px-4">
                    {t.natt_enabled ? (
                      <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 text-[10px]">
                        NAT-T (UDP 4500)
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px]">
                        Direct (IP 50)
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4">
                    <SeverityBadge severity={t.risk_level} />
                  </td>
                  <td className="py-2.5 px-4 font-semibold text-red-600">{t.findings_count}</td>
                  <td className="py-2.5 px-4">
                    <button
                      onClick={() => onNavigate('tunnels', t.id)}
                      className="text-blue-700 hover:text-blue-900 font-sans font-semibold text-xs"
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 3: Risk Distribution and Capture Frame Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Breakdown */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="text-xs uppercase font-bold text-slate-700 tracking-wider mb-3">
            Explainable Risk Contributors
          </div>
          {risk?.contributors && risk.contributors.length > 0 ? (
            <div className="space-y-2">
              {risk.contributors.slice(0, 5).map((c, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-50 border border-slate-200 text-xs">
                  <div>
                    <div className="font-semibold text-slate-800">{c.title}</div>
                    <div className="text-[11px] text-slate-500 font-mono">
                      Rule: {c.rule_id} • Category: {c.category}
                    </div>
                  </div>
                  <div className="text-right font-mono">
                    <span className="text-red-600 font-bold">+{c.points} pts</span>
                    <div className="text-[10px] text-slate-400">Conf: {Math.round(c.confidence * 100)}%</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 text-center py-6">No major risk contributors.</div>
          )}
        </div>

        {/* Capture Frame Breakdown */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="text-xs uppercase font-bold text-slate-700 tracking-wider mb-3">
            Capture Protocol Breakdown
          </div>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs font-semibold text-slate-700 mb-1">
                <span>IKE Control Traffic (UDP 500)</span>
                <span className="font-mono">{selectedCapture?.ike_packet_count} pkts</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full"
                  style={{
                    width: `${((selectedCapture?.ike_packet_count ?? 0) / Math.max(1, selectedCapture?.packet_count ?? 1)) * 100}%`
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold text-slate-700 mb-1">
                <span>ESP Encrypted Data (IP 50)</span>
                <span className="font-mono">{selectedCapture?.esp_packet_count} pkts</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2">
                <div
                  className="bg-indigo-600 h-2 rounded-full"
                  style={{
                    width: `${((selectedCapture?.esp_packet_count ?? 0) / Math.max(1, selectedCapture?.packet_count ?? 1)) * 100}%`
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold text-slate-700 mb-1">
                <span>NAT-Traversal Encapsulation (UDP 4500)</span>
                <span className="font-mono">{selectedCapture?.natt_packet_count} pkts</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2">
                <div
                  className="bg-emerald-600 h-2 rounded-full"
                  style={{
                    width: `${((selectedCapture?.natt_packet_count ?? 0) / Math.max(1, selectedCapture?.packet_count ?? 1)) * 100}%`
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold text-slate-700 mb-1">
                <span>Other Transit Traffic</span>
                <span className="font-mono">{selectedCapture?.other_packet_count} pkts</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2">
                <div
                  className="bg-slate-400 h-2 rounded-full"
                  style={{
                    width: `${((selectedCapture?.other_packet_count ?? 0) / Math.max(1, selectedCapture?.packet_count ?? 1)) * 100}%`
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
