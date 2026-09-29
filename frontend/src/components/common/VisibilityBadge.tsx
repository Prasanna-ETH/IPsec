import React from 'react';
import { EvidenceType } from '../../types';
import { Eye, Cpu, HelpCircle, Lock } from 'lucide-react';

interface Props {
  type: EvidenceType;
  confidence?: number;
  showConfidence?: boolean;
}

export const VisibilityBadge: React.FC<Props> = ({ type, confidence = 1.0, showConfidence = true }) => {
  if (type === 'OBSERVED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded bg-blue-50 text-blue-800 border border-blue-200">
        <Eye className="w-3 h-3 text-blue-600" />
        OBSERVED {showConfidence && '(100%)'}
      </span>
    );
  }

  if (type === 'DERIVED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded bg-slate-100 text-slate-800 border border-slate-300">
        <Cpu className="w-3 h-3 text-slate-600" />
        DERIVED {showConfidence && '(100%)'}
      </span>
    );
  }

  if (type === 'INFERRED') {
    const pct = Math.round(confidence * 100);
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded bg-amber-50 text-amber-800 border border-amber-200">
        <HelpCircle className="w-3 h-3 text-amber-600" />
        INFERRED {showConfidence && `(${pct}%)`}
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded bg-gray-100 text-gray-600 border border-gray-200" title="Unavailable from passive encrypted observation">
      <Lock className="w-3 h-3 text-gray-500" />
      UNOBSERVABLE
    </span>
  );
};
