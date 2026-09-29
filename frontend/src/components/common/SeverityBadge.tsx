import React from 'react';
import { Severity } from '../../types';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, CheckCircle2 } from 'lucide-react';

interface Props {
  severity: Severity | string;
}

export const SeverityBadge: React.FC<Props> = ({ severity }) => {
  const sev = (severity || 'INFORMATIONAL').toUpperCase();

  switch (sev) {
    case 'CRITICAL':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-bold rounded bg-red-50 text-red-700 border border-red-200">
          <AlertOctagon className="w-3 h-3 text-red-600" />
          CRITICAL
        </span>
      );
    case 'HIGH':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded bg-orange-50 text-orange-700 border border-orange-200">
          <AlertTriangle className="w-3 h-3 text-orange-600" />
          HIGH
        </span>
      );
    case 'MEDIUM':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded bg-amber-50 text-amber-700 border border-amber-200">
          <AlertCircle className="w-3 h-3 text-amber-600" />
          MEDIUM
        </span>
      );
    case 'LOW':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded bg-blue-50 text-blue-700 border border-blue-200">
          <Info className="w-3 h-3 text-blue-600" />
          LOW
        </span>
      );
    case 'COMPLIANT':
    case 'SECURE':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
          <CheckCircle2 className="w-3 h-3 text-emerald-600" />
          COMPLIANT
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded bg-slate-100 text-slate-700 border border-slate-200">
          <Info className="w-3 h-3 text-slate-500" />
          {sev}
        </span>
      );
  }
};
