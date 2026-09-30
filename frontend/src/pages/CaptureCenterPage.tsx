import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import { CaptureSummary } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import {
  UploadCloud,
  FileCheck2,
  HardDrive,
  Clock,
  CheckCircle2,
  AlertCircle,
  Play,
  RotateCcw,
  Layers,
  ArrowRight
} from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const CaptureCenterPage: React.FC<Props> = ({ onNavigate }) => {
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(null);
  const [analysisStage, setAnalysisStage] = useState<string>('');
  const [analysisPercent, setAnalysisPercent] = useState<number>(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadCaptures();
  }, []);

  // Poll analysis status when active
  useEffect(() => {
    let interval: any;
    if (activeAnalysisId) {
      interval = setInterval(async () => {
        try {
          const status = await api.getCaptureStatus(activeAnalysisId);
          setAnalysisStage(status.current_stage || 'Processing');
          setAnalysisPercent(status.stage_progress || 0);

          if (status.status === 'COMPLETED' || status.status === 'COMPLETED_WITH_LIMITATIONS' || status.status === 'FAILED') {
            setActiveAnalysisId(null);
            loadCaptures();
          }
        } catch (e) {
          console.error(e);
        }
      }, 800);
    }
    return () => clearInterval(interval);
  }, [activeAnalysisId]);

  const loadCaptures = async () => {
    try {
      const caps = await api.getCaptures();
      setCaptures(caps);
    } catch (e) {
      console.error(e);
    }
  };

  const handleFileUpload = async (file: File) => {
    try {
      setIsUploading(true);
      setUploadProgress(20);
      const res = await api.uploadCapture(file);
      setUploadProgress(100);
      setActiveAnalysisId(res.id);
      setAnalysisStage(res.current_stage || '1. Validating capture');
      setAnalysisPercent(res.stage_progress || 10);
      loadCaptures();
    } catch (e: any) {
      alert(`Upload failed: ${e.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const handleLoadSample = async (sampleName: string) => {
    try {
      setIsUploading(true);
      const res = await api.loadSampleCapture(sampleName);
      setActiveAnalysisId(res.id);
      setAnalysisStage(res.current_stage || '1. Validating capture');
      setAnalysisPercent(res.stage_progress || 10);
      loadCaptures();
    } catch (e: any) {
      alert(`Failed to load sample: ${e.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Description */}
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">Capture Ingestion Center</h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Ingest raw PCAP / PCAPNG network traces for passive cryptographic classification, SA correlation, and standards assessment.
        </p>
      </div>

      {/* Upload Box */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        className="bg-white border-2 border-dashed border-slate-300 hover:border-blue-500 rounded p-8 text-center transition-colors shadow-xs"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileChange}
          className="hidden"
        />

        <UploadCloud className="w-10 h-10 text-slate-400 mx-auto mb-3" />
        <h3 className="text-sm font-bold text-slate-800">Select or drop a network capture file</h3>
        <p className="text-xs text-slate-500 mt-1 mb-4">
          Supported formats: <span className="font-mono font-semibold">.pcap</span>, <span className="font-mono font-semibold">.pcapng</span> (Air-gapped local processing only)
        </p>

        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={isUploading || !!activeAnalysisId}
          className="px-4 py-2 bg-blue-700 hover:bg-blue-800 disabled:bg-slate-400 text-white rounded text-xs font-semibold shadow-xs"
        >
          {isUploading ? 'Uploading file...' : 'BROWSE LOCAL PCAP'}
        </button>
      </div>

      {/* Quick Ingest Testbed Captures */}
      <div className="bg-white border border-slate-200 rounded p-5 shadow-xs">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-2">
          <Layers className="w-4 h-4 text-blue-600" />
          Pre-Generated Testbed Network Captures (One-Click Ingestion)
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Sample 1: Hardened */}
          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded hover:border-blue-300 transition-colors flex flex-col justify-between">
            <div>
              <div className="font-bold text-slate-900 text-xs">ikev2_hardened_aes_gcm.pcap</div>
              <div className="text-[11px] text-slate-500 mt-1">
                Modern IKEv2 handshake, AES-256-GCM AEAD encryption, Diffie-Hellman Group 19 (ECP-256), compliant bidirectional ESP.
              </div>
            </div>
            <button
              onClick={() => handleLoadSample('ikev2_hardened_aes_gcm')}
              disabled={isUploading || !!activeAnalysisId}
              className="mt-3 w-full py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded text-xs font-semibold"
            >
              Analyze Modern IKEv2
            </button>
          </div>

          {/* Sample 2: Legacy */}
          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded hover:border-red-300 transition-colors flex flex-col justify-between">
            <div>
              <div className="font-bold text-slate-900 text-xs">ikev1_legacy_3des_sha1.pcap</div>
              <div className="text-[11px] text-slate-500 mt-1">
                Deprecated IKEv1 Aggressive Mode, 3DES-CBC, MD5/SHA1 integrity, Group 2 (MODP-1024), and ESP sequence drop gaps.
              </div>
            </div>
            <button
              onClick={() => handleLoadSample('ikev1_legacy_3des_sha1')}
              disabled={isUploading || !!activeAnalysisId}
              className="mt-3 w-full py-1.5 bg-red-800 hover:bg-red-900 text-white rounded text-xs font-semibold"
            >
              Analyze Legacy 3DES Trace
            </button>
          </div>

          {/* Sample 3: NAT-T */}
          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded hover:border-emerald-300 transition-colors flex flex-col justify-between">
            <div>
              <div className="font-bold text-slate-900 text-xs">natt_traversal_esp.pcap</div>
              <div className="text-[11px] text-slate-500 mt-1">
                UDP port 4500 NAT-Traversal encapsulated ESP stream traversing edge stateful NAT/firewall boundaries.
              </div>
            </div>
            <button
              onClick={() => handleLoadSample('natt_traversal_esp')}
              disabled={isUploading || !!activeAnalysisId}
              className="mt-3 w-full py-1.5 bg-emerald-800 hover:bg-emerald-900 text-white rounded text-xs font-semibold"
            >
              Analyze NAT-T (UDP 4500)
            </button>
          </div>

          {/* Sample 4: 4-Tunnel Multi-Scenario Learning PCAP */}
          <div className="p-3.5 bg-indigo-50/50 border border-indigo-200 rounded hover:border-indigo-400 transition-colors flex flex-col justify-between">
            <div>
              <div className="font-bold text-indigo-950 text-xs flex items-center justify-between">
                <span>omega_4_tunnel_learning.pcap</span>
                <span className="text-[9px] bg-indigo-200/60 text-indigo-800 px-1.5 py-0.5 rounded font-mono">4 TUNNELS</span>
              </div>
              <div className="text-[11px] text-slate-600 mt-1">
                Comprehensive trace: 4 distinct tunnels (Compliant IKEv2, Legacy 3DES, Sequence Gaps, Replay/Duplicates, and NAT-T 4500).
              </div>
            </div>
            <button
              onClick={() => handleLoadSample('omega_4_tunnel_learning')}
              disabled={isUploading || !!activeAnalysisId}
              className="mt-3 w-full py-1.5 bg-indigo-700 hover:bg-indigo-800 text-white rounded text-xs font-semibold"
            >
              Analyze 4-Tunnel Trace
            </button>
          </div>
        </div>
      </div>

      {/* 12-Stage Active Analysis Progress Bar */}
      {activeAnalysisId && (
        <div className="bg-slate-900 text-slate-100 p-5 rounded border border-slate-800 shadow-md">
          <div className="flex justify-between items-center mb-2">
            <div className="flex items-center gap-2 text-xs font-bold text-blue-400">
              <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping" />
              12-STAGE DETERMINISTIC ANALYSIS IN PROGRESS
            </div>
            <span className="font-mono text-xs text-slate-400">{analysisPercent}%</span>
          </div>

          <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden mb-3">
            <div
              className="bg-blue-600 h-2.5 rounded-full transition-all duration-300"
              style={{ width: `${analysisPercent}%` }}
            />
          </div>

          <div className="text-xs font-mono text-slate-300">
            Current Stage: <span className="text-white font-semibold">{analysisStage}</span>
          </div>
        </div>
      )}

      {/* Historical Captures Table */}
      <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 flex justify-between items-center">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-slate-600" />
            Analyzed Captures Archive
          </div>
          <button
            onClick={loadCaptures}
            className="text-slate-500 hover:text-slate-700 p-1 rounded hover:bg-slate-200 text-xs flex items-center gap-1"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Filename</th>
                <th className="py-2.5 px-4">SHA-256</th>
                <th className="py-2.5 px-4">Size</th>
                <th className="py-2.5 px-4">Packets (IKE/ESP/NAT-T)</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Risk Posture</th>
                <th className="py-2.5 px-4">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {captures.map((c) => (
                <tr key={c.id} className="hover:bg-slate-50 text-[12px]">
                  <td className="py-2.5 px-4 font-bold text-slate-900 flex items-center gap-2">
                    <FileCheck2 className="w-4 h-4 text-blue-600 shrink-0" />
                    {c.filename}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[11px] text-slate-500">
                    {c.sha256 ? `${c.sha256.slice(0, 16)}...` : 'N/A'}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-600">
                    {(c.file_size / 1024).toFixed(1)} KB
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-700">
                    <span className="font-bold">{c.packet_count}</span> total (
                    <span className="text-blue-700">{c.ike_packet_count}</span>/
                    <span className="text-indigo-700">{c.esp_packet_count}</span>/
                    <span className="text-emerald-700">{c.natt_packet_count}</span>)
                  </td>
                  <td className="py-2.5 px-4">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold ${
                        c.status === 'COMPLETED'
                          ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                          : c.status === 'COMPLETED_WITH_LIMITATIONS'
                          ? 'bg-amber-50 text-amber-800 border border-amber-200'
                          : c.status === 'FAILED'
                          ? 'bg-red-50 text-red-800 border border-red-200'
                          : 'bg-blue-50 text-blue-800 border border-blue-200'
                      }`}
                    >
                      {c.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-4">
                    <SeverityBadge severity={c.overall_risk_level} />
                  </td>
                  <td className="py-2.5 px-4">
                    <button
                      onClick={() => onNavigate('overview')}
                      className="text-blue-700 hover:text-blue-900 font-semibold text-xs flex items-center gap-1"
                    >
                      Inspect <ArrowRight className="w-3 h-3" />
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
