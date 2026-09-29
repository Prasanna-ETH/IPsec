import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { CaptureSummary } from '../types';
import { FileText, Download, FileCheck, HardDrive, Clock, CheckCircle2 } from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const ReportsPage: React.FC<Props> = ({ onNavigate }) => {
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');
  const [reports, setReports] = useState<any[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [caps, reps] = await Promise.all([api.getCaptures(), api.getReports()]);
      setCaptures(caps);
      setReports(reps);
      if (caps.length > 0) {
        setSelectedCaptureId(caps[0].id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (type: 'PDF' | 'JSON') => {
    if (!selectedCaptureId) return;
    try {
      setIsGenerating(true);
      const res = await api.generateReport(selectedCaptureId, type);
      // Reload reports
      const reps = await api.getReports();
      setReports(reps);
      // Trigger instant download
      window.open(res.download_url, '_blank');
    } catch (e: any) {
      alert(`Report generation failed: ${e.message}`);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">
          Security Assessment Reports
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Generate formal audit-grade PDF assessment documents and structured JSON machine-readable artifacts.
        </p>
      </div>

      {/* Generator Card */}
      <div className="bg-white border border-slate-200 rounded p-6 shadow-xs">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-4">
          Generate Assessment Report
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-end">
          <div>
            <label className="text-xs font-semibold text-slate-600 block mb-1">
              Select Analyzed Target Capture
            </label>
            <select
              value={selectedCaptureId}
              onChange={(e) => setSelectedCaptureId(e.target.value)}
              className="w-full bg-slate-50 border border-slate-300 rounded px-3 py-2 text-xs font-bold text-slate-900 focus:outline-none focus:ring-1 focus:ring-blue-600"
            >
              {captures.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} (Risk: {c.overall_risk_score}/100 • SHA256: {c.sha256.slice(0, 10)}...)
                </option>
              ))}
            </select>
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => handleGenerateReport('PDF')}
              disabled={isGenerating || !selectedCaptureId}
              className="flex-1 px-4 py-2 bg-blue-700 hover:bg-blue-800 disabled:bg-slate-400 text-white rounded text-xs font-bold flex items-center justify-center gap-2 shadow-xs"
            >
              <FileText className="w-4 h-4" />
              {isGenerating ? 'Generating PDF...' : 'GENERATE PDF REPORT'}
            </button>

            <button
              onClick={() => handleGenerateReport('JSON')}
              disabled={isGenerating || !selectedCaptureId}
              className="flex-1 px-4 py-2 bg-slate-800 hover:bg-slate-900 disabled:bg-slate-400 text-white rounded text-xs font-bold flex items-center justify-center gap-2 shadow-xs"
            >
              <Download className="w-4 h-4" />
              GENERATE JSON
            </button>
          </div>
        </div>
      </div>

      {/* Historical Generated Reports Table */}
      <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
        <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 font-bold text-xs uppercase text-slate-700 flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-slate-600" />
          Generated Assessment Reports Archive ({reports.length})
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Report File</th>
                <th className="py-2.5 px-4">Format</th>
                <th className="py-2.5 px-4">SHA-256 Hash</th>
                <th className="py-2.5 px-4">Generated Time</th>
                <th className="py-2.5 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-[12px]">
              {reports.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50">
                  <td className="py-2.5 px-4 font-bold text-slate-900 flex items-center gap-2 font-sans">
                    <FileCheck className="w-4 h-4 text-blue-700 shrink-0" />
                    {r.filename}
                  </td>
                  <td className="py-2.5 px-4 font-bold">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        r.report_type === 'PDF'
                          ? 'bg-red-50 text-red-800 border border-red-200'
                          : 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                      }`}
                    >
                      {r.report_type}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-500 text-[11px]">
                    {r.sha256 ? `${r.sha256.slice(0, 16)}...` : 'N/A'}
                  </td>
                  <td className="py-2.5 px-4 text-slate-600 font-sans text-[11px]">
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td className="py-2.5 px-4 font-sans">
                    <a
                      href={r.download_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-blue-700 hover:text-blue-900 font-bold text-xs"
                    >
                      <Download className="w-3.5 h-3.5" /> Download
                    </a>
                  </td>
                </tr>
              ))}

              {reports.length === 0 && (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-slate-500 font-sans text-xs">
                    No reports generated yet. Click above to generate assessment reports.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
