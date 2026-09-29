import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Tunnel, IKESession, ESPSA, TimelineEvent, Finding, DigitalTwin } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { VisibilityBadge } from '../components/common/VisibilityBadge';
import { DigitalTwinViewer } from '../components/common/DigitalTwinViewer';
import {
  Network,
  Radio,
  Shield,
  Clock,
  ShieldAlert,
  Cpu,
  Layers,
  ArrowLeft,
  Eye,
  Activity,
  AlertTriangle
} from 'lucide-react';

interface Props {
  tunnelId: string;
  onBack: () => void;
  onNavigate: (route: string, param?: string) => void;
}

type TabType = 'SUMMARY' | 'IKE' | 'ESP' | 'LIFECYCLE' | 'FINDINGS' | 'DIGITAL_TWIN';

export const TunnelInvestigationPage: React.FC<Props> = ({ tunnelId, onBack, onNavigate }) => {
  const [activeTab, setActiveTab] = useState<TabType>('SUMMARY');
  const [tunnel, setTunnel] = useState<Tunnel | null>(null);
  const [ikeSessions, setIkeSessions] = useState<IKESession[]>([]);
  const [espSas, setEspSas] = useState<ESPSA[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [digitalTwin, setDigitalTwin] = useState<DigitalTwin | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTunnelData();
  }, [tunnelId]);

  const loadTunnelData = async () => {
    try {
      setLoading(true);
      const [tData, ikeData, espData, tlData, twinData] = await Promise.all([
        api.getTunnel(tunnelId),
        api.getTunnelIke(tunnelId),
        api.getTunnelEsp(tunnelId),
        api.getTunnelTimeline(tunnelId),
        api.getTunnelDigitalTwin(tunnelId)
      ]);
      setTunnel(tData);
      setIkeSessions(ikeData);
      setEspSas(espData);
      setTimeline(tlData);
      setDigitalTwin(twinData);

      // Load findings for this tunnel
      const allFindings = await api.getFindings({ tunnel_id: tunnelId });
      setFindings(allFindings);
    } catch (e) {
      console.error('Error loading tunnel investigation:', e);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !tunnel) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 font-mono text-xs">
        LOADING TUNNEL INVESTIGATION WORKSTATION...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header bar with Back button */}
      <div className="flex items-center justify-between bg-white p-4 rounded border border-slate-200">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-1.5 rounded hover:bg-slate-100 text-slate-600 border border-slate-300 text-xs flex items-center gap-1"
          >
            <ArrowLeft className="w-4 h-4" /> Back
          </button>
          <div>
            <div className="text-xs uppercase font-semibold text-slate-500">Tunnel Investigation</div>
            <div className="font-mono font-extrabold text-base text-slate-900">{tunnel.tunnel_key}</div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-[10px] uppercase font-bold text-slate-400">Security Posture</div>
            <SeverityBadge severity={tunnel.risk_level} />
          </div>
          <div className="text-right font-mono border-l border-slate-200 pl-3">
            <div className="text-[10px] uppercase text-slate-400 font-sans">Packets / Volume</div>
            <div className="text-xs font-bold text-slate-800">
              {tunnel.packet_count} pkts ({(tunnel.byte_count / 1024).toFixed(1)} KB)
            </div>
          </div>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex border-b border-slate-200 bg-white rounded-t px-2">
        <button
          onClick={() => setActiveTab('SUMMARY')}
          className={`py-3 px-4 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
            activeTab === 'SUMMARY'
              ? 'border-blue-700 text-blue-800 bg-blue-50/50'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Network className="w-3.5 h-3.5" /> SUMMARY
        </button>

        <button
          onClick={() => setActiveTab('IKE')}
          className={`py-3 px-4 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
            activeTab === 'IKE'
              ? 'border-blue-700 text-blue-800 bg-blue-50/50'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Radio className="w-3.5 h-3.5" /> IKE HANDSHAKE & PROPOSALS ({ikeSessions.length})
        </button>

        <button
          onClick={() => setActiveTab('ESP')}
          className={`py-3 px-4 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
            activeTab === 'ESP'
              ? 'border-blue-700 text-blue-800 bg-blue-50/50'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Layers className="w-3.5 h-3.5" /> ESP FLOW INTELLIGENCE ({espSas.length})
        </button>

        <button
          onClick={() => setActiveTab('LIFECYCLE')}
          className={`py-3 px-4 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
            activeTab === 'LIFECYCLE'
              ? 'border-blue-700 text-blue-800 bg-blue-50/50'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Clock className="w-3.5 h-3.5" /> SA LIFECYCLE TIMELINE ({timeline.length})
        </button>

        <button
          onClick={() => setActiveTab('FINDINGS')}
          className={`py-3 px-4 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
            activeTab === 'FINDINGS'
              ? 'border-blue-700 text-blue-800 bg-blue-50/50'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-red-600" /> FINDINGS ({findings.length})
        </button>

        <button
          onClick={() => setActiveTab('DIGITAL_TWIN')}
          className={`py-3 px-4 text-xs font-bold border-b-2 flex items-center gap-1.5 ${
            activeTab === 'DIGITAL_TWIN'
              ? 'border-blue-700 text-blue-800 bg-blue-50/50'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-indigo-600" /> DIGITAL TWIN
        </button>
      </div>

      {/* Tab 1: SUMMARY */}
      {activeTab === 'SUMMARY' && (
        <div className="space-y-6">
          {/* Topology Reconstruction */}
          <div className="bg-slate-900 text-white p-5 rounded border border-slate-800">
            <div className="text-xs uppercase font-mono text-slate-400 mb-4">
              Passive Topology Reconstruction
            </div>
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="bg-slate-800 border border-slate-700 p-3 rounded text-center w-full sm:w-56">
                <div className="text-[11px] text-slate-400 font-mono">PEER A (INITIATOR)</div>
                <div className="font-mono font-bold text-sm mt-1">{tunnel.endpoint_a}</div>
              </div>

              <div className="flex-1 flex flex-col items-center px-4 w-full">
                <div className="text-xs font-mono text-blue-400 bg-blue-950 px-2 py-0.5 rounded border border-blue-800 mb-1">
                  {tunnel.ike_version || 'IKE Protocol'} • {tunnel.natt_enabled ? 'NAT-T (4500)' : 'IP 50'}
                </div>
                <div className="w-full h-0.5 bg-blue-500/40 relative flex items-center justify-center">
                  <div className="w-2 h-2 rounded-full bg-blue-400" />
                </div>
                <div className="text-[10px] text-slate-400 font-mono mt-1">
                  {espSas.length} Active Child SAs
                </div>
              </div>

              <div className="bg-slate-800 border border-slate-700 p-3 rounded text-center w-full sm:w-56">
                <div className="text-[11px] text-slate-400 font-mono">PEER B (RESPONDER)</div>
                <div className="font-mono font-bold text-sm mt-1">{tunnel.endpoint_b}</div>
              </div>
            </div>
          </div>

          {/* Quick Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-white border border-slate-200 rounded p-4">
              <div className="text-xs font-semibold text-slate-500 uppercase">IKE Handshake Status</div>
              <div className="text-sm font-bold font-mono text-slate-800 mt-1">
                {tunnel.ike_version ? `${tunnel.ike_version} Active` : 'No IKE frames captured'}
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {ikeSessions.length} Handshake exchange sessions
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded p-4">
              <div className="text-xs font-semibold text-slate-500 uppercase">NAT Traversal</div>
              <div className="text-sm font-bold font-mono text-slate-800 mt-1">
                {tunnel.natt_enabled ? 'Active (UDP 4500)' : 'Disabled (Direct IP 50)'}
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {tunnel.natt_enabled ? 'NAT gateway traversed' : 'Direct public or routed IP'}
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded p-4">
              <div className="text-xs font-semibold text-slate-500 uppercase">Active Duration</div>
              <div className="text-sm font-bold font-mono text-slate-800 mt-1">
                {tunnel.duration} seconds
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {tunnel.packet_count} packets processed
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: IKE HANDSHAKE & PROPOSALS */}
      {activeTab === 'IKE' && (
        <div className="space-y-6">
          {ikeSessions.map((sess, idx) => (
            <div key={sess.id || idx} className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
              <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex justify-between items-center text-xs">
                <div className="font-bold text-slate-800 flex items-center gap-2">
                  <Radio className="w-4 h-4 text-blue-600" />
                  <span>Session: {sess.ike_version} ({sess.exchange_type || 'Exchange'})</span>
                </div>
                <div className="font-mono text-slate-500">
                  Init SPI: <span className="font-bold text-slate-800">{sess.initiator_spi}</span> • Resp SPI: <span className="font-bold text-slate-800">{sess.responder_spi || '0x00000000'}</span>
                </div>
              </div>

              <div className="p-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 mb-2">
                  Extracted Cryptographic Proposals
                </h4>
                {sess.proposals && sess.proposals.length > 0 ? (
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                        <th className="py-2 px-3">Prop #</th>
                        <th className="py-2 px-3">Encryption</th>
                        <th className="py-2 px-3">Key Length</th>
                        <th className="py-2 px-3">PRF</th>
                        <th className="py-2 px-3">Integrity</th>
                        <th className="py-2 px-3">DH Group</th>
                        <th className="py-2 px-3">Assessment</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                      {sess.proposals.map((p, pIdx) => (
                        <tr key={p.id || pIdx} className="hover:bg-slate-50">
                          <td className="py-2 px-3 font-bold">{p.proposal_number}</td>
                          <td className="py-2 px-3 text-slate-900 font-bold">{p.encryption_alg}</td>
                          <td className="py-2 px-3">{p.key_length ? `${p.key_length} bits` : 'Default'}</td>
                          <td className="py-2 px-3">{p.prf_alg || 'None'}</td>
                          <td className="py-2 px-3">{p.integrity_alg || 'None'}</td>
                          <td className="py-2 px-3 text-slate-900 font-bold">{p.dh_group}</td>
                          <td className="py-2 px-3">
                            <SeverityBadge severity={p.assessment} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="text-xs text-slate-500 font-mono py-2">
                    Proposal transform bodies encrypted or not present in this exchange.
                  </div>
                )}
              </div>
            </div>
          ))}

          {ikeSessions.length === 0 && (
            <div className="bg-white border border-slate-200 rounded p-8 text-center text-xs text-slate-500 font-mono">
              No IKE handshakes captured in this specific trace.
            </div>
          )}
        </div>
      )}

      {/* Tab 3: ESP FLOW INTELLIGENCE */}
      {activeTab === 'ESP' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 font-bold text-xs uppercase text-slate-700">
              ESP Security Association Flow Registry
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-100 text-slate-600 font-semibold uppercase text-[11px]">
                    <th className="py-2.5 px-4">SPI</th>
                    <th className="py-2.5 px-4">Direction</th>
                    <th className="py-2.5 px-4">Packets</th>
                    <th className="py-2.5 px-4">Bytes</th>
                    <th className="py-2.5 px-4">Seq Range</th>
                    <th className="py-2.5 px-4">Gaps</th>
                    <th className="py-2.5 px-4">Replays</th>
                    <th className="py-2.5 px-4">Mean Size</th>
                    <th className="py-2.5 px-4">Mean IAT</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[12px]">
                  {espSas.map((sa) => (
                    <tr key={sa.id} className="hover:bg-slate-50">
                      <td className="py-2.5 px-4 font-bold text-blue-800">{sa.spi}</td>
                      <td className="py-2.5 px-4 font-sans font-medium text-slate-700">{sa.direction}</td>
                      <td className="py-2.5 px-4 text-slate-900 font-bold">{sa.packet_count}</td>
                      <td className="py-2.5 px-4 text-slate-600">{(sa.byte_count / 1024).toFixed(1)} KB</td>
                      <td className="py-2.5 px-4">{sa.min_seq} → {sa.max_seq}</td>
                      <td className="py-2.5 px-4 text-amber-700 font-bold">{sa.sequence_gaps}</td>
                      <td className="py-2.5 px-4 text-red-700 font-bold">{sa.replay_suspect_count}</td>
                      <td className="py-2.5 px-4">{sa.mean_packet_size} B</td>
                      <td className="py-2.5 px-4">{(sa.mean_iat * 1000).toFixed(1)} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: SA LIFECYCLE TIMELINE */}
      {activeTab === 'LIFECYCLE' && (
        <div className="bg-white border border-slate-200 rounded p-6 shadow-xs">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-6">
            Forensic SA Lifecycle Timeline
          </h3>

          <div className="relative border-l-2 border-slate-200 ml-4 space-y-6">
            {timeline.map((ev, idx) => (
              <div key={idx} className="relative pl-6">
                {/* Marker Dot */}
                <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-white border-2 border-blue-600 flex items-center justify-center" />

                <div className="bg-slate-50 border border-slate-200 rounded p-3 text-xs">
                  <div className="flex items-center justify-between font-mono mb-1">
                    <span className="font-bold text-blue-900">{ev.time_display} (+{ev.relative_seconds}s)</span>
                    <VisibilityBadge type={ev.evidence_type} confidence={1.0} showConfidence={false} />
                  </div>
                  <div className="font-semibold text-slate-800 text-sm">{ev.summary}</div>
                  {ev.frame_number && (
                    <div className="text-[11px] text-slate-500 font-mono mt-1">
                      Frame Reference: Frame #{ev.frame_number}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 5: FINDINGS */}
      {activeTab === 'FINDINGS' && (
        <div className="space-y-4">
          {findings.map((f) => (
            <div key={f.id} className="bg-white border border-slate-200 rounded p-4 shadow-xs">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="font-mono text-xs text-slate-500">{f.rule_id}</span>
                    <VisibilityBadge type={f.evidence_type} confidence={f.confidence} />
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 mt-1">{f.title}</h3>
                  <div className="text-xs text-slate-600 mt-1">{f.description}</div>
                </div>
              </div>

              <div className="mt-3 p-2.5 rounded bg-slate-50 border border-slate-200 text-xs font-mono text-slate-800">
                <span className="font-bold text-slate-600">Technical Evidence:</span> {f.technical_evidence}
              </div>

              <div className="mt-2 text-xs text-slate-500 flex justify-between items-center">
                <span>Standard: <strong className="text-slate-700">{f.standards_reference}</strong></span>
                <span className="font-mono">Confidence: {Math.round(f.confidence * 100)}%</span>
              </div>
            </div>
          ))}

          {findings.length === 0 && (
            <div className="bg-white border border-slate-200 rounded p-8 text-center text-xs text-slate-500 font-mono">
              No security anomalies or compliance findings for this tunnel.
            </div>
          )}
        </div>
      )}

      {/* Tab 6: DIGITAL TWIN */}
      {activeTab === 'DIGITAL_TWIN' && digitalTwin && (
        <DigitalTwinViewer twin={digitalTwin} />
      )}
    </div>
  );
};
