import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { SystemStatus } from '../types';
import {
  Server,
  Lock,
  Cpu,
  HardDrive,
  CheckCircle2,
  AlertCircle,
  Database,
  Shield,
  Activity
} from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const SystemPage: React.FC<Props> = ({ onNavigate }) => {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const data = await api.getSystemStatus();
      setStatus(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !status) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 font-mono text-xs">
        CONNECTING TO LOCAL SOVEREIGN ENGINE...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">
          Sovereign & Air-Gapped Engine Status
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Local analysis node telemetry, privacy boundaries, and cryptographic subsystem health.
        </p>
      </div>

      {/* Air-Gapped Compliance Assurance Card */}
      <div className="bg-[#0A192F] text-white p-6 rounded border border-slate-800 shadow-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-4 border-b border-slate-800 gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded flex items-center justify-center text-white font-bold text-lg">
              Ω
            </div>
            <div>
              <div className="text-sm font-bold text-slate-100">{status.project_name} SOVEREIGN PLATFORM</div>
              <div className="text-xs text-slate-400">{status.project_subtitle}</div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-emerald-950/80 border border-emerald-700 text-emerald-300 rounded font-mono text-xs font-bold">
              <CheckCircle2 className="w-3.5 h-3.5" /> AIR-GAPPED VERIFIED
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
            <div className="text-[10px] text-slate-400">EXTERNAL APIS / LLMS</div>
            <div className="text-emerald-400 font-bold mt-0.5">{status.external_apis}</div>
          </div>

          <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
            <div className="text-[10px] text-slate-400">CLOUD ANALYSIS</div>
            <div className="text-emerald-400 font-bold mt-0.5">{status.cloud_analysis}</div>
          </div>

          <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
            <div className="text-[10px] text-slate-400">TELEMETRY & TRACKING</div>
            <div className="text-emerald-400 font-bold mt-0.5">{status.telemetry}</div>
          </div>

          <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
            <div className="text-[10px] text-slate-400">CORE DEPLOYMENT MODE</div>
            <div className="text-blue-400 font-bold mt-0.5">{status.deployment_mode}</div>
          </div>
        </div>
      </div>

      {/* Subsystem Specifications */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Software Versions */}
        <div className="bg-white border border-slate-200 rounded p-5 shadow-xs">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-1.5">
            <Cpu className="w-4 h-4 text-slate-600" />
            Subsystem & Rule-Pack Versions
          </h3>
          <dl className="divide-y divide-slate-100 text-xs font-mono">
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">OMEGA Engine Version:</dt>
              <dd className="font-bold text-slate-800">{status.version}</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">Deterministic Rule-Pack:</dt>
              <dd className="font-bold text-slate-800">{status.rulepack_version}</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">XGBoost ML Behavioral Classifier:</dt>
              <dd className="font-bold text-slate-800">{status.ml_model_version}</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">Loaded Security Rules:</dt>
              <dd className="font-bold text-blue-700">{status.active_rules_count} Rules Active</dd>
            </div>
          </dl>
        </div>

        {/* Local Storage & Pipeline Health */}
        <div className="bg-white border border-slate-200 rounded p-5 shadow-xs">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-1.5">
            <Database className="w-4 h-4 text-slate-600" />
            Storage & Native Integrations
          </h3>
          <dl className="divide-y divide-slate-100 text-xs font-mono">
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">Database Backend:</dt>
              <dd className="font-bold text-slate-800">{status.database_status}</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">tshark / Wireshark Utility:</dt>
              <dd className={`font-bold ${status.tshark_available ? 'text-emerald-700' : 'text-slate-600'}`}>
                {status.tshark_available ? 'Installed & Bound' : 'Scapy / Native Dpkt Pipeline (Active)'}
              </dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">Ingested Captures:</dt>
              <dd className="font-bold text-slate-800">{status.active_captures_count} records</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-slate-500 font-sans font-medium">Active VPN Tunnels:</dt>
              <dd className="font-bold text-slate-800">{status.active_tunnels_count} sessions</dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  );
};
