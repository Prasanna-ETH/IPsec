import React from 'react';
import { DigitalTwin } from '../../types';
import { VisibilityBadge } from './VisibilityBadge';
import { Network, Shield, Key, Eye, HelpCircle, Lock } from 'lucide-react';

interface Props {
  twin: DigitalTwin;
}

export const DigitalTwinViewer: React.FC<Props> = ({ twin }) => {
  return (
    <div className="space-y-6">
      {/* Topology Diagram */}
      <div className="bg-slate-900 text-slate-100 p-5 rounded border border-slate-800">
        <div className="text-xs uppercase font-semibold text-slate-400 mb-4 tracking-wider flex items-center gap-1.5">
          <Network className="w-4 h-4 text-blue-400" />
          Passive Topological Reconstruction (Digital Twin)
        </div>

        <div className="flex flex-col md:flex-row items-center justify-between gap-4 py-2">
          {/* Endpoint A */}
          <div className="bg-slate-800 border border-slate-700 p-3 rounded text-center w-full md:w-56">
            <div className="text-xs text-slate-400 font-mono">PEER ENDPOINT A</div>
            <div className="font-mono font-bold text-white text-sm mt-1">{twin.endpoint_a}</div>
            <div className="text-xs text-emerald-400 mt-1">Initiator Context</div>
          </div>

          {/* IKE SA Connection */}
          <div className="flex-1 flex flex-col items-center px-4 w-full">
            <div className="text-xs font-mono text-blue-400 bg-blue-950/80 px-2.5 py-1 rounded border border-blue-800/60 mb-2">
              {twin.observed.ike_version || 'IKE Protocol'} • {twin.observed.natt_encapsulation || 'IP 50'}
            </div>
            <div className="w-full h-0.5 bg-blue-500/50 relative flex items-center justify-center">
              <div className="w-2 h-2 rounded-full bg-blue-400" />
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-2 text-center">
              DH: {twin.observed.dh_group || 'N/A'} • PRF: {twin.observed.prf_transform || 'N/A'}
            </div>
          </div>

          {/* Endpoint B */}
          <div className="bg-slate-800 border border-slate-700 p-3 rounded text-center w-full md:w-56">
            <div className="text-xs text-slate-400 font-mono">PEER ENDPOINT B</div>
            <div className="font-mono font-bold text-white text-sm mt-1">{twin.endpoint_b}</div>
            <div className="text-xs text-blue-400 mt-1">Responder Context</div>
          </div>
        </div>

        {/* ESP Child SA Bar */}
        <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-indigo-400" />
            <span>ESP Security Associations:</span>
            <span className="text-slate-200">
              {Array.isArray(twin.observed.esp_spi_list) ? twin.observed.esp_spi_list.join(', ') : 'None'}
            </span>
          </div>
          <div>Duration: {twin.derived.tunnel_duration_seconds}s ({twin.derived.total_packets} packets)</div>
        </div>
      </div>

      {/* 4-Tier Visibility Boundary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* OBSERVED (100%) */}
        <div className="bg-white border border-blue-200 rounded p-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-blue-100">
            <div className="font-bold text-blue-900 text-sm flex items-center gap-1.5">
              <Eye className="w-4 h-4 text-blue-600" />
              OBSERVED (Direct Cleartext Headers)
            </div>
            <VisibilityBadge type="OBSERVED" confidence={1.0} />
          </div>
          <dl className="grid grid-cols-2 gap-2 text-xs">
            <dt className="text-slate-500 font-medium">IKE Version:</dt>
            <dd className="font-mono text-slate-800">{twin.observed.ike_version || 'N/A'}</dd>

            <dt className="text-slate-500 font-medium">Encapsulation:</dt>
            <dd className="font-mono text-slate-800">{twin.observed.natt_encapsulation || 'N/A'}</dd>

            <dt className="text-slate-500 font-medium">Initiator SPI:</dt>
            <dd className="font-mono text-slate-800">{twin.observed.initiator_spi || 'N/A'}</dd>

            <dt className="text-slate-500 font-medium">Responder SPI:</dt>
            <dd className="font-mono text-slate-800">{twin.observed.responder_spi || 'N/A'}</dd>

            <dt className="text-slate-500 font-medium">Encryption Transform:</dt>
            <dd className="font-mono text-slate-800">{twin.observed.encryption_transform || 'N/A'}</dd>

            <dt className="text-slate-500 font-medium">DH Key Exchange:</dt>
            <dd className="font-mono text-slate-800">{twin.observed.dh_group || 'N/A'}</dd>
          </dl>
        </div>

        {/* DERIVED (100%) */}
        <div className="bg-white border border-slate-300 rounded p-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-200">
            <div className="font-bold text-slate-900 text-sm flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-slate-700" />
              DERIVED (Deterministically Computed)
            </div>
            <VisibilityBadge type="DERIVED" confidence={1.0} />
          </div>
          <dl className="grid grid-cols-2 gap-2 text-xs">
            <dt className="text-slate-500 font-medium">Total Volume:</dt>
            <dd className="font-mono text-slate-800">{twin.derived.total_packets} pkts ({(twin.derived.total_bytes / 1024).toFixed(1)} KB)</dd>

            <dt className="text-slate-500 font-medium">Active ESP SAs:</dt>
            <dd className="font-mono text-slate-800">{twin.derived.active_esp_sa_count}</dd>

            <dt className="text-slate-500 font-medium">Sequence Continuity:</dt>
            <dd className="font-mono text-slate-800">{twin.derived.sequence_continuity}</dd>

            <dt className="text-slate-500 font-medium">Anti-Replay Status:</dt>
            <dd className="font-mono text-slate-800">{twin.derived.replay_status}</dd>
          </dl>
        </div>

        {/* INFERRED (Probabilistic / Statistical) */}
        <div className="bg-white border border-amber-200 rounded p-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-amber-100">
            <div className="font-bold text-amber-900 text-sm flex items-center gap-1.5">
              <HelpCircle className="w-4 h-4 text-amber-600" />
              INFERRED (Statistical / Flow Dynamics)
            </div>
            <VisibilityBadge type="INFERRED" confidence={0.85} />
          </div>
          <dl className="grid grid-cols-2 gap-2 text-xs">
            <dt className="text-slate-500 font-medium">Flow Profile:</dt>
            <dd className="font-mono text-slate-800">{twin.inferred.flow_behavioral_profile}</dd>

            <dt className="text-slate-500 font-medium">Burst Dynamics:</dt>
            <dd className="font-mono text-slate-800">{twin.inferred.burst_profile}</dd>

            <dt className="text-slate-500 font-medium">Traffic Symmetry:</dt>
            <dd className="font-mono text-slate-800">{twin.inferred.traffic_symmetry}</dd>
          </dl>
        </div>

        {/* UNOBSERVABLE (Cryptographically Protected) */}
        <div className="bg-slate-50 border border-slate-300 rounded p-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-200">
            <div className="font-bold text-slate-700 text-sm flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-slate-500" />
              UNOBSERVABLE (Strict Epistemic Limit)
            </div>
            <VisibilityBadge type="UNOBSERVABLE" />
          </div>
          <ul className="space-y-1 text-xs text-slate-600 list-disc list-inside font-mono">
            {Object.entries(twin.unobservable || {}).map(([key, desc]) => (
              <li key={key} className="text-[11px] leading-tight">
                <span className="font-semibold text-slate-800">{key.replace(/_/g, ' ')}:</span> {desc}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
