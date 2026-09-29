import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { VisibilityBadge } from '../components/common/VisibilityBadge';
import { BookOpen, ShieldCheck, FileCode, CheckCircle2 } from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const StandardsPage: React.FC<Props> = ({ onNavigate }) => {
  const [rulesData, setRulesData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await api.getRules();
      setRulesData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !rulesData) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 font-mono text-xs">
        LOADING STANDARDS & AUDITABLE RULE PACK...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">
          Standards Compliance & Auditable Rule Pack
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Deterministic declarative YAML security rules mapped to RFC 8247, RFC 7296, RFC 9395, and NIST SP 800-77 Rev. 1.
        </p>
      </div>

      {/* Standards Citation Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="font-mono text-[11px] text-blue-700 font-bold uppercase">RFC 8247 / RFC 8221</div>
          <div className="font-bold text-slate-800 text-sm mt-1">Cryptographic Algorithm Implementation</div>
          <p className="text-xs text-slate-600 mt-1">
            Mandates modern cipher suites (AES-GCM, Curve25519, Group 19/20) and deprecates 3DES, DES, RC4, MD5, SHA1.
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="font-mono text-[11px] text-blue-700 font-bold uppercase">NIST SP 800-77 Rev. 1</div>
          <div className="font-bold text-slate-800 text-sm mt-1">Guide to IPsec VPNs</div>
          <p className="text-xs text-slate-600 mt-1">
            National Institute of Standards baseline specifying minimum 112/128-bit security strength and periodic rekey intervals.
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
          <div className="font-mono text-[11px] text-blue-700 font-bold uppercase">RFC 9395</div>
          <div className="font-bold text-slate-800 text-sm mt-1">Deprecation of IKEv1</div>
          <p className="text-xs text-slate-600 mt-1">
            Formal IETF classification of IKEv1 and Aggressive Mode as deprecated due to offline dictionary attacks and legacy designs.
          </p>
        </div>
      </div>

      {/* Rules Registry Table */}
      <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
        <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex justify-between items-center">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <FileCode className="w-4 h-4 text-slate-600" />
            Loaded Rule Pack (v{rulesData.rulepack_version}) — {rulesData.total_rules} Active Deterministic Rules
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2.5 px-4">Rule ID</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Title & Condition</th>
                <th className="py-2.5 px-4">Category</th>
                <th className="py-2.5 px-4">Evidence Type</th>
                <th className="py-2.5 px-4">Citation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-[12px]">
              {rulesData.rules.map((r: any, idx: number) => (
                <tr key={idx} className="hover:bg-slate-50">
                  <td className="py-3 px-4 font-mono font-bold text-slate-900">{r.id}</td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="py-3 px-4">
                    <div className="font-bold text-slate-900">{r.title}</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                      field: <strong>{r.condition?.field}</strong> {r.condition?.operator} {JSON.stringify(r.condition?.values)}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-600">{r.category}</td>
                  <td className="py-3 px-4">
                    <VisibilityBadge type={r.evidence_type} confidence={1.0} showConfidence={false} />
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-700">
                    {r.standards_reference}
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
