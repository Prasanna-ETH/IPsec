import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Tunnel, CaptureSummary } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { Network, ArrowRight, ShieldCheck, Activity } from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const TunnelsPage: React.FC<Props> = ({ onNavigate }) => {
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadCapturesAndTunnels();
  }, []);

  const loadCapturesAndTunnels = async () => {
    try {
      setLoading(true);
      const caps = await api.getCaptures();
      setCaptures(caps);
      if (caps.length > 0) {
        setSelectedCaptureId(caps[0].id);
        const tList = await api.getCaptureTunnels(caps[0].id);
        setTunnels(tList);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleCaptureChange = async (capId: string) => {
    setSelectedCaptureId(capId);
    try {
      const tList = await api.getCaptureTunnels(capId);
      setTunnels(tList);
    } catch (e) {
      console.error(e);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 font-mono text-xs">
        LOADING TUNNEL REGISTRY...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">IPsec Tunnel Explorer</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Cryptographic tunnel sessions reconstructed through passive header observation.
          </p>
        </div>

        {/* Capture Selector */}
        {captures.length > 0 && (
          <select
            value={selectedCaptureId}
            onChange={(e) => handleCaptureChange(e.target.value)}
            className="font-bold text-slate-800 bg-white border border-slate-300 rounded px-3 py-1.5 text-xs shadow-xs focus:ring-1 focus:ring-blue-600"
          >
            {captures.map((c) => (
              <option key={c.id} value={c.id}>
                Target: {c.filename} ({c.packet_count} packets)
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Tunnels Table */}
      <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <Network className="w-4 h-4 text-slate-600" />
            Detected IPsec VPN Tunnels ({tunnels.length})
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Tunnel ID / Key</th>
                <th className="py-2.5 px-4">Endpoint A</th>
                <th className="py-2.5 px-4">Endpoint B</th>
                <th className="py-2.5 px-4">IKE Version</th>
                <th className="py-2.5 px-4">Encapsulation</th>
                <th className="py-2.5 px-4">IKE SAs</th>
                <th className="py-2.5 px-4">ESP SAs</th>
                <th className="py-2.5 px-4">Duration</th>
                <th className="py-2.5 px-4">Risk Posture</th>
                <th className="py-2.5 px-4">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {tunnels.map((t) => (
                <tr key={t.id} className="hover:bg-slate-50 font-mono text-[12px]">
                  <td className="py-3 px-4 font-bold text-slate-900">{t.tunnel_key}</td>
                  <td className="py-3 px-4 text-slate-700">{t.endpoint_a}</td>
                  <td className="py-3 px-4 text-slate-700">{t.endpoint_b}</td>
                  <td className="py-3 px-4 font-sans font-semibold text-slate-800">
                    {t.ike_version || 'Not observed'}
                  </td>
                  <td className="py-3 px-4">
                    {t.natt_enabled ? (
                      <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 text-[10px] font-sans font-medium">
                        NAT-T (4500)
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-sans font-medium">
                        Direct (IP 50)
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-slate-700">{t.ike_sessions_count}</td>
                  <td className="py-3 px-4 text-slate-700">{t.esp_sas_count}</td>
                  <td className="py-3 px-4 text-slate-600">{t.duration}s</td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={t.risk_level} />
                  </td>
                  <td className="py-3 px-4">
                    <button
                      onClick={() => onNavigate('tunnels', t.id)}
                      className="px-2.5 py-1 bg-blue-700 hover:bg-blue-800 text-white rounded text-xs font-sans font-semibold flex items-center gap-1 shadow-xs"
                    >
                      Investigate <ArrowRight className="w-3 h-3" />
                    </button>
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
