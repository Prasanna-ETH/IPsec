import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { PacketMetadata, CaptureSummary } from '../types';
import { FileSearch, Search, Filter, Layers, Radio, Shield, HardDrive, Terminal } from 'lucide-react';

interface Props {
  onNavigate: (route: string, param?: string) => void;
}

export const EvidenceExplorerPage: React.FC<Props> = ({ onNavigate }) => {
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');
  const [packets, setPackets] = useState<PacketMetadata[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [selectedPacket, setSelectedPacket] = useState<PacketMetadata | null>(null);
  const [page, setPage] = useState(1);
  const [protocolFilter, setProtocolFilter] = useState<string>('');
  const [spiFilter, setSpiFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadCaptures();
  }, []);

  useEffect(() => {
    if (selectedCaptureId) {
      loadPackets();
    }
  }, [selectedCaptureId, page, protocolFilter, spiFilter, searchQuery]);

  const loadCaptures = async () => {
    try {
      setLoading(true);
      const caps = await api.getCaptures();
      setCaptures(caps);
      if (caps.length > 0) {
        setSelectedCaptureId(caps[0].id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const loadPackets = async () => {
    try {
      const res = await api.getPackets(selectedCaptureId, {
        page,
        page_size: 40,
        protocol: protocolFilter || undefined,
        spi: spiFilter || undefined,
        search: searchQuery || undefined,
      });
      setPackets(res.packets);
      setTotalPackets(res.total);
      if (res.packets.length > 0 && !selectedPacket) {
        setSelectedPacket(res.packets[0]);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const formatHex = (hexStr?: string) => {
    if (!hexStr) return 'No raw bytes captured';
    const chunks = hexStr.match(/.{1,2}/g) || [];
    return chunks.join(' ').toUpperCase();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">Evidence & Packet Explorer</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Wireshark-grade frame-level evidence tree and raw packet metadata verification.
          </p>
        </div>

        {/* Target Capture Selector */}
        {captures.length > 0 && (
          <select
            value={selectedCaptureId}
            onChange={(e) => {
              setSelectedCaptureId(e.target.value);
              setPage(1);
            }}
            className="font-bold text-slate-800 bg-white border border-slate-300 rounded px-3 py-1.5 text-xs shadow-xs focus:ring-1 focus:ring-blue-600"
          >
            {captures.map((c) => (
              <option key={c.id} value={c.id}>
                Capture: {c.filename} ({c.packet_count} packets)
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-white border border-slate-200 rounded p-3 shadow-xs flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, summary..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              className="pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-300 rounded text-xs focus:outline-none focus:ring-1 focus:ring-blue-600 w-48 font-medium"
            />
          </div>

          {/* SPI Search */}
          <input
            type="text"
            placeholder="Filter SPI (e.g. 0x...)"
            value={spiFilter}
            onChange={(e) => {
              setSpiFilter(e.target.value);
              setPage(1);
            }}
            className="px-3 py-1.5 bg-slate-50 border border-slate-300 rounded text-xs focus:outline-none focus:ring-1 focus:ring-blue-600 w-36 font-mono"
          />

          {/* Protocol filter buttons */}
          <div className="flex rounded border border-slate-300 overflow-hidden bg-slate-100">
            {['', 'IKE', 'ESP', 'NAT-T'].map((proto) => (
              <button
                key={proto}
                onClick={() => {
                  setProtocolFilter(proto);
                  setPage(1);
                }}
                className={`px-3 py-1 text-xs font-semibold ${
                  protocolFilter === proto
                    ? 'bg-blue-700 text-white'
                    : 'text-slate-600 hover:bg-slate-200'
                }`}
              >
                {proto || 'All'}
              </button>
            ))}
          </div>
        </div>

        <div className="text-slate-500 font-mono text-[11px]">
          Total: {totalPackets} frames (Page {page})
        </div>
      </div>

      {/* Split Pane: Packet Table (Top) and Inspector (Bottom) */}
      <div className="space-y-4">
        {/* Packet Table */}
        <div className="bg-white border border-slate-200 rounded shadow-xs overflow-hidden max-h-80 overflow-y-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-slate-100 border-b border-slate-200 z-10 shadow-xs">
              <tr className="text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-2 px-3 w-16">No.</th>
                <th className="py-2 px-3 w-24">Time (s)</th>
                <th className="py-2 px-3 w-36">Source</th>
                <th className="py-2 px-3 w-36">Destination</th>
                <th className="py-2 px-3 w-24">Protocol</th>
                <th className="py-2 px-3 w-20">Length</th>
                <th className="py-2 px-3">Summary / Header Info</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
              {packets.map((p) => {
                const isSelected = selectedPacket?.id === p.id;
                return (
                  <tr
                    key={p.id}
                    onClick={() => setSelectedPacket(p)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-blue-100/70 text-blue-950 font-bold'
                        : 'hover:bg-slate-50 text-slate-800'
                    }`}
                  >
                    <td className="py-1.5 px-3 text-slate-500">{p.frame_number}</td>
                    <td className="py-1.5 px-3 text-slate-600">{p.timestamp.toFixed(4)}</td>
                    <td className="py-1.5 px-3">{p.source_ip}</td>
                    <td className="py-1.5 px-3">{p.destination_ip}</td>
                    <td className="py-1.5 px-3 font-sans font-semibold">
                      <span
                        className={`px-1.5 py-0.2 rounded text-[10px] ${
                          p.is_ike
                            ? 'bg-blue-100 text-blue-800 border border-blue-200'
                            : p.is_esp
                            ? 'bg-indigo-100 text-indigo-800 border border-indigo-200'
                            : p.is_natt
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                            : 'bg-slate-100 text-slate-700 border border-slate-200'
                        }`}
                      >
                        {p.protocol}
                      </span>
                    </td>
                    <td className="py-1.5 px-3 text-slate-500">{p.length} B</td>
                    <td className="py-1.5 px-3 truncate max-w-xs font-sans text-slate-700">
                      {p.summary}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Packet Inspector & Hex Pane */}
        {selectedPacket && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Decoded Field Tree */}
            <div className="bg-white border border-slate-200 rounded p-4 shadow-xs">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-700 pb-2 mb-3 border-b border-slate-200 flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-blue-600" />
                  Frame #{selectedPacket.frame_number} Protocol Tree
                </div>
                <span className="font-mono text-[11px] text-slate-500">{selectedPacket.protocol}</span>
              </div>

              <div className="space-y-3 text-xs font-mono">
                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded">
                  <div className="font-bold text-slate-800 mb-1">Internet Protocol (IP) Layer</div>
                  <div className="text-slate-600">Source: <span className="text-slate-900 font-bold">{selectedPacket.source_ip}</span></div>
                  <div className="text-slate-600">Destination: <span className="text-slate-900 font-bold">{selectedPacket.destination_ip}</span></div>
                  <div className="text-slate-600">Frame Length: <span className="text-slate-900">{selectedPacket.length} bytes</span></div>
                </div>

                {selectedPacket.detailed_json && Object.keys(selectedPacket.detailed_json).length > 0 && (
                  <div className="p-2.5 bg-blue-50/50 border border-blue-200 rounded">
                    <div className="font-bold text-blue-900 mb-1">Parsed Cryptographic Payload Fields</div>
                    <pre className="text-[11px] text-slate-800 whitespace-pre-wrap">
                      {JSON.stringify(selectedPacket.detailed_json, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>

            {/* Raw Hex Viewer */}
            <div className="bg-slate-900 text-slate-200 rounded p-4 border border-slate-800 font-mono text-xs">
              <div className="text-xs font-bold uppercase text-slate-400 pb-2 mb-3 border-b border-slate-800 flex items-center justify-between">
                <span>Packet Byte Stream (First 64 Bytes)</span>
                <span className="text-[10px] text-slate-500">HEX OFFSET</span>
              </div>

              <div className="p-2 bg-slate-950 rounded text-emerald-400 text-[11px] leading-relaxed break-all">
                {formatHex(selectedPacket.raw_hex_preview)}
              </div>

              <div className="mt-4 text-[10px] text-slate-400">
                Passive capture preserves cryptographic byte integrity without modifying or decrypting ciphertext.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
