import {
  CaptureSummary, PacketMetadata, Tunnel, IKESession, ESPSA,
  FlowWindow, Finding, TimelineEvent, DigitalTwin, RiskAssessment,
  ComparisonResponse, SystemStatus
} from '../types';

const API_BASE = import.meta.env.VITE_API_BASE_URL
  ? `${import.meta.env.VITE_API_BASE_URL}/api/v1`
  : '/api/v1';

export const api = {
  // Captures
  async getCaptures(): Promise<CaptureSummary[]> {
    const res = await fetch(`${API_BASE}/captures`);
    if (!res.ok) throw new Error('Failed to fetch captures');
    return res.json();
  },

  async getCapture(id: string): Promise<CaptureSummary> {
    const res = await fetch(`${API_BASE}/captures/${id}`);
    if (!res.ok) throw new Error('Failed to fetch capture details');
    return res.json();
  },

  async getCaptureStatus(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/captures/${id}/status`);
    if (!res.ok) throw new Error('Failed to fetch capture status');
    return res.json();
  },

  async uploadCapture(file: File): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/captures`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  async loadSampleCapture(sampleName: string): Promise<any> {
    const res = await fetch(`${API_BASE}/captures/sample/${sampleName}`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to load sample capture');
    }
    return res.json();
  },

  async getPackets(
    captureId: string,
    params: {
      page?: number;
      page_size?: number;
      protocol?: string;
      is_ike?: boolean;
      is_esp?: boolean;
      is_natt?: boolean;
      spi?: string;
      search?: string;
    } = {}
  ): Promise<{ total: number; page: number; page_size: number; packets: PacketMetadata[] }> {
    const q = new URLSearchParams();
    if (params.page) q.append('page', params.page.toString());
    if (params.page_size) q.append('page_size', params.page_size.toString());
    if (params.protocol) q.append('protocol', params.protocol);
    if (params.is_ike !== undefined) q.append('is_ike', String(params.is_ike));
    if (params.is_esp !== undefined) q.append('is_esp', String(params.is_esp));
    if (params.is_natt !== undefined) q.append('is_natt', String(params.is_natt));
    if (params.spi) q.append('spi', params.spi);
    if (params.search) q.append('search', params.search);

    const res = await fetch(`${API_BASE}/captures/${captureId}/packets?${q.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch packets');
    return res.json();
  },

  async getCaptureTunnels(captureId: string): Promise<Tunnel[]> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/tunnels`);
    if (!res.ok) throw new Error('Failed to fetch capture tunnels');
    return res.json();
  },

  async getCaptureFindings(captureId: string): Promise<Finding[]> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/findings`);
    if (!res.ok) throw new Error('Failed to fetch capture findings');
    return res.json();
  },

  async getCaptureRisk(captureId: string): Promise<RiskAssessment> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/risk`);
    if (!res.ok) throw new Error('Failed to fetch capture risk');
    return res.json();
  },

  // Tunnels
  async getTunnel(id: string): Promise<Tunnel> {
    const res = await fetch(`${API_BASE}/tunnels/${id}`);
    if (!res.ok) throw new Error('Failed to fetch tunnel');
    return res.json();
  },

  async getTunnelIke(id: string): Promise<IKESession[]> {
    const res = await fetch(`${API_BASE}/tunnels/${id}/ike`);
    if (!res.ok) throw new Error('Failed to fetch IKE sessions');
    return res.json();
  },

  async getTunnelEsp(id: string): Promise<ESPSA[]> {
    const res = await fetch(`${API_BASE}/tunnels/${id}/esp`);
    if (!res.ok) throw new Error('Failed to fetch ESP SAs');
    return res.json();
  },

  async getTunnelWindows(id: string): Promise<FlowWindow[]> {
    const res = await fetch(`${API_BASE}/tunnels/${id}/windows`);
    if (!res.ok) throw new Error('Failed to fetch flow windows');
    return res.json();
  },

  async getTunnelTimeline(id: string): Promise<TimelineEvent[]> {
    const res = await fetch(`${API_BASE}/tunnels/${id}/timeline`);
    if (!res.ok) throw new Error('Failed to fetch tunnel timeline');
    return res.json();
  },

  async getTunnelDigitalTwin(id: string): Promise<DigitalTwin> {
    const res = await fetch(`${API_BASE}/tunnels/${id}/digital_twin`);
    if (!res.ok) throw new Error('Failed to fetch digital twin');
    return res.json();
  },

  // Findings
  async getFindings(params: {
    severity?: string;
    category?: string;
    evidence_type?: string;
    capture_id?: string;
    tunnel_id?: string;
    search?: string;
  } = {}): Promise<Finding[]> {
    const q = new URLSearchParams();
    if (params.severity) q.append('severity', params.severity);
    if (params.category) q.append('category', params.category);
    if (params.evidence_type) q.append('evidence_type', params.evidence_type);
    if (params.capture_id) q.append('capture_id', params.capture_id);
    if (params.tunnel_id) q.append('tunnel_id', params.tunnel_id);
    if (params.search) q.append('search', params.search);

    const res = await fetch(`${API_BASE}/findings?${q.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async getFinding(id: string): Promise<Finding> {
    const res = await fetch(`${API_BASE}/findings/${id}`);
    if (!res.ok) throw new Error('Failed to fetch finding');
    return res.json();
  },

  // Reports
  async generateReport(captureId: string, type: 'PDF' | 'JSON'): Promise<any> {
    const res = await fetch(`${API_BASE}/reports/${captureId}?report_type=${type}`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to generate report');
    return res.json();
  },

  async getReports(): Promise<any[]> {
    const res = await fetch(`${API_BASE}/reports`);
    if (!res.ok) throw new Error('Failed to fetch reports');
    return res.json();
  },

  // Compare
  async compareCaptures(baselineId: string, remediationId: string): Promise<ComparisonResponse> {
    const res = await fetch(`${API_BASE}/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseline_capture_id: baselineId,
        remediation_capture_id: remediationId,
      }),
    });
    if (!res.ok) throw new Error('Failed to compare captures');
    return res.json();
  },

  // System & Rules
  async getSystemStatus(): Promise<SystemStatus> {
    const res = await fetch(`${API_BASE}/system/status`);
    if (!res.ok) throw new Error('Failed to fetch system status');
    return res.json();
  },

  async getRules(): Promise<any> {
    const res = await fetch(`${API_BASE}/rules`);
    if (!res.ok) throw new Error('Failed to fetch rules');
    return res.json();
  },
};
