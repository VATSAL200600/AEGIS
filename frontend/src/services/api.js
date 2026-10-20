/**
 * AEGIS Frontend API Service
 * Interacts with FastAPI backend endpoints via relative /api URL (proxied by Vite)
 */

const BASE_URL = '/api';

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  };

  try {
    const res = await fetch(url, config);
    if (!res.ok) {
      let errMsg = `Request failed: ${res.status} ${res.statusText}`;
      try {
        const errorJson = await res.json();
        if (errorJson.error && errorJson.error.message) {
          errMsg = errorJson.error.message;
        } else if (errorJson.detail) {
          errMsg = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
        }
      } catch (_) {}
      throw new Error(errMsg);
    }
    const json = await res.json();
    return json.data !== undefined ? json.data : json;
  } catch (err) {
    console.warn(`[API] ${endpoint} error:`, err.message);
    throw err;
  }
}

// System
export async function getHealth() {
  return request('/health');
}

// Dashboard
export async function getDashboardStats(scanId = null) {
  const query = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
  return request(`/dashboard${query}`);
}

// Scans
export async function listScans({ page = 1, limit = 20, status = '', domain = '' } = {}) {
  const params = new URLSearchParams();
  if (page) params.set('page', page);
  if (limit) params.set('limit', limit);
  if (status) params.set('status', status);
  if (domain) params.set('domain', domain);
  const q = params.toString() ? `?${params.toString()}` : '';
  return request(`/scans${q}`);
}

export async function createScan({ target_domain, scan_profile = 'standard', enable_threat_intel = true, enable_port_scan = true }) {
  return request('/scans', {
    method: 'POST',
    body: JSON.stringify({
      target_domain,
      scan_profile,
      enable_threat_intel,
      enable_port_scan,
    }),
  });
}

export async function getScan(scanId) {
  return request(`/scans/${scanId}`);
}

// Assets
export async function listAssets({ scan_id, domain, risk_level, search, limit = 100, offset = 0 } = {}) {
  const params = new URLSearchParams();
  if (scan_id) params.set('scan_id', scan_id);
  if (domain) params.set('domain', domain);
  if (risk_level) params.set('risk_level', risk_level);
  if (search) params.set('search', search);
  if (limit) params.set('limit', limit);
  if (offset) params.set('offset', offset);
  const q = params.toString() ? `?${params.toString()}` : '';
  return request(`/assets${q}`);
}

export async function getAsset(assetId) {
  return request(`/assets/${assetId}`);
}

// Reports
export async function listReports(scanId = null) {
  const q = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
  return request(`/reports${q}`);
}

export async function getReport(reportId) {
  return request(`/reports/${reportId}`);
}

export async function generateReport({ scan_id, report_type = 'executive', provider = 'gemini' }) {
  return request('/reports', {
    method: 'POST',
    body: JSON.stringify({
      scan_id,
      report_type,
      provider,
    }),
  });
}

export function getReportHtmlUrl(reportId) {
  return `${BASE_URL}/reports/${reportId}/html`;
}

export async function getInsiderTelemetry(scanId = null) {
  const q = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
  return request(`/reports/insider-telemetry${q}`);
}
