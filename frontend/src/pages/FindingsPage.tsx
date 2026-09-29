import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Finding, CaptureSummary } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { VisibilityBadge } from '../components/common/VisibilityBadge';
import { ShieldAlert, Filter, Search, BookOpen, ExternalLink, X } from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const FindingsPage: React.FC<Props> = ({ onNavigate }) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [evidenceFilter, setEvidenceFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFindings();
  }, [severityFilter, categoryFilter, evidenceFilter, searchQuery]);

  const loadFindings = async () => {
    try {
      setLoading(true);
      const data = await api.getFindings({
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
        evidence_type: evidenceFilter || undefined,
        search: searchQuery || undefined
      });
      setFindings(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">Security Findings & Posture</h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Deterministic compliance violations, cryptographic deprecations, and encrypted flow anomalies.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="bg-white border border-slate-200 rounded p-4 shadow-xs flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search rule ID, title, RFC..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-300 rounded text-xs focus:ring-1 focus:ring-blue-600 focus:outline-none w-56 font-medium"
            />
          </div>

          {/* Severity Select */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-slate-50 border border-slate-300 rounded text-xs font-medium focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>

          {/* Category Select */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-slate-50 border border-slate-300 rounded text-xs font-medium focus:outline-none"
          >
            <option value="">All Categories</option>
            <option value="CRYPTO">Cryptography</option>
            <option value="KEY_MGMT">Key Management</option>
            <option value="PROTOCOL">Protocol Compliance</option>
            <option value="ANOMALY">Statistical Anomaly</option>
            <option value="METADATA">Metadata Exposure</option>
          </select>

          {/* Evidence Type Select */}
          <select
            value={evidenceFilter}
            onChange={(e) => setEvidenceFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-slate-50 border border-slate-300 rounded text-xs font-medium focus:outline-none"
          >
            <option value="">All Evidence Types</option>
            <option value="OBSERVED">Observed (100%)</option>
            <option value="DERIVED">Derived (100%)</option>
            <option value="INFERRED">Inferred (Probabilistic)</option>
          </select>
        </div>

        <div className="text-slate-500 font-mono text-[11px]">
          Showing {findings.length} findings
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Rule ID</th>
                <th className="py-2.5 px-4">Finding Title</th>
                <th className="py-2.5 px-4">Category</th>
                <th className="py-2.5 px-4">Evidence Type</th>
                <th className="py-2.5 px-4">Standards Reference</th>
                <th className="py-2.5 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {findings.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className="hover:bg-slate-50 cursor-pointer text-[12px]"
                >
                  <td className="py-2.5 px-4">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="py-2.5 px-4 font-mono font-bold text-slate-800">{f.rule_id}</td>
                  <td className="py-2.5 px-4 font-semibold text-slate-900">{f.title}</td>
                  <td className="py-2.5 px-4 font-mono text-slate-600">{f.category}</td>
                  <td className="py-2.5 px-4">
                    <VisibilityBadge type={f.evidence_type} confidence={f.confidence} />
                  </td>
                  <td className="py-2.5 px-4 text-slate-600 font-mono text-[11px]">
                    {f.standards_reference}
                  </td>
                  <td className="py-2.5 px-4">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedFinding(f);
                      }}
                      className="text-blue-700 hover:text-blue-900 font-semibold text-xs"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Detail Modal / Drawer */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 flex items-center justify-center p-4 backdrop-blur-xs">
          <div className="bg-white rounded border border-slate-300 max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-xl p-6">
            <div className="flex justify-between items-start pb-3 border-b border-slate-200">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={selectedFinding.severity} />
                  <span className="font-mono text-xs text-slate-500 font-bold">{selectedFinding.rule_id}</span>
                  <VisibilityBadge type={selectedFinding.evidence_type} confidence={selectedFinding.confidence} />
                </div>
                <h2 className="text-base font-extrabold text-slate-900">{selectedFinding.title}</h2>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="py-4 space-y-4 text-xs">
              {/* Description */}
              <div>
                <div className="font-bold text-slate-700 uppercase tracking-wider text-[11px] mb-1">Description</div>
                <div className="text-slate-700 leading-relaxed">{selectedFinding.description}</div>
              </div>

              {/* Technical Evidence */}
              <div>
                <div className="font-bold text-slate-700 uppercase tracking-wider text-[11px] mb-1">Technical Evidence</div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded font-mono text-slate-900">
                  {selectedFinding.technical_evidence}
                </div>
              </div>

              {/* Standards Reference & Recommendation */}
              <div className="grid grid-cols-1 gap-3">
                <div className="p-3 bg-blue-50/60 border border-blue-200 rounded">
                  <div className="font-bold text-blue-900 uppercase tracking-wider text-[11px] mb-0.5 flex items-center gap-1.5">
                    <BookOpen className="w-3.5 h-3.5 text-blue-700" />
                    Standards Citation
                  </div>
                  <div className="text-blue-950 font-mono">{selectedFinding.standards_reference}</div>
                </div>

                <div className="p-3 bg-emerald-50/60 border border-emerald-200 rounded">
                  <div className="font-bold text-emerald-900 uppercase tracking-wider text-[11px] mb-0.5">
                    Remediation Recommendation
                  </div>
                  <div className="text-emerald-950 font-medium">{selectedFinding.recommendation}</div>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-200 flex justify-end">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
