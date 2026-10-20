import React, { useState, useEffect } from 'react';
import { listAssets } from '../../services/api';

export default function AssetInventoryPage({ activeTarget = 'example.com', onSelectAsset }) {
  const [assets, setAssets] = useState(() => getMockAssets());
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [selectedRisk, setSelectedRisk] = useState('ALL');
  const [selectedTag, setSelectedTag] = useState('');

  const loadAssets = async () => {
    try {
      const riskParam = selectedRisk !== 'ALL' ? selectedRisk.toLowerCase() : undefined;
      const res = await listAssets({
        search: search || undefined,
        risk_level: riskParam,
        limit: 100,
      });

      if (Array.isArray(res) && res.length > 0) {
        setAssets(res);
      } else {
        // High fidelity mock fallback if database is fresh or empty
        const mock = getMockAssets();
        const filteredMock = mock.filter((a) => {
          if (riskParam && a.risk_level?.toLowerCase() !== riskParam) return false;
          if (search) {
            const q = search.toLowerCase();
            return a.hostname?.toLowerCase().includes(q) || a.ip_address?.includes(q);
          }
          return true;
        });
        setAssets(filteredMock.length > 0 ? filteredMock : mock);
      }
    } catch (err) {
      console.warn('Failed to load assets, using fallback dataset:', err);
      setAssets(getMockAssets());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, [selectedRisk, search]);

  const filteredAssets = assets.filter((asset) => {
    if (search) {
      const q = search.toLowerCase();
      const matchHost = asset.hostname?.toLowerCase().includes(q);
      const matchIp = asset.ip_address?.toLowerCase().includes(q);
      const matchTech = asset.technologies?.some((t) => t.toLowerCase().includes(q));
      if (!matchHost && !matchIp && !matchTech) return false;
    }

    if (selectedRisk !== 'ALL') {
      if (asset.risk_level?.toLowerCase() !== selectedRisk.toLowerCase()) return false;
    }

    if (selectedTag === 'EXPOSED_PORTS') {
      const hasCriticalPort = asset.open_ports?.some((p) => [3389, 445, 23, 27017, 3306].includes(p));
      if (!hasCriticalPort) return false;
    }

    if (selectedTag === 'EXPIRED_SSL') {
      if (asset.ssl_status !== 'expired') return false;
    }

    return true;
  });

  // Risk Pill Counts
  const counts = {
    ALL: assets.length,
    CRITICAL: assets.filter((a) => a.risk_level === 'critical').length,
    HIGH: assets.filter((a) => a.risk_level === 'high').length,
    MEDIUM: assets.filter((a) => a.risk_level === 'medium').length,
    LOW: assets.filter((a) => a.risk_level === 'low').length,
    INFO: assets.filter((a) => a.risk_level === 'info').length,
  };

  return (
    <div className="flex flex-col w-full gap-space-lg">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-md">
        <div>
          <h1 className="font-headline text-2xl font-bold text-on-surface tracking-tight">
            Attack Surface Asset Inventory
          </h1>
          <p className="text-xs text-secondary">
            Discovered subdomains, network topology, exposed ports, and technology stacks
          </p>
        </div>
        <div className="flex items-center gap-space-xs">
          <button
            onClick={() => {
              const jsonStr = JSON.stringify(filteredAssets, null, 2);
              const blob = new Blob([jsonStr], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `aegis-assets-${activeTarget}.json`;
              a.click();
            }}
            className="h-8 px-space-sm bg-surface-container-low hover:bg-surface-container text-on-surface text-xs font-semibold rounded flex items-center gap-1 transition-colors"
          >
            <span className="material-symbols-outlined text-[16px]">download</span>
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-surface-container-lowest rounded-xl shadow-sm p-space-md border border-surface-variant/40 flex flex-col gap-space-md">
        {/* Search */}
        <div className="relative w-full">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-[18px]">
            search
          </span>
          <input
            type="text"
            className="w-full h-10 pl-10 pr-24 bg-surface-container-low hover:bg-surface-container text-on-surface rounded font-mono text-xs focus:bg-surface-container-lowest focus:outline-none focus:ring-2 focus:ring-primary-container transition-all"
            placeholder="Search hostname, IP, ASN, port, or technology (e.g. 104.21, RDP, nginx, AS16509)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-outline hover:text-on-surface text-xs font-mono"
            >
              clear
            </button>
          )}
        </div>

        {/* Severity Status Chips */}
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-space-md pt-space-xs border-t border-surface-variant/30">
          <div className="flex items-center gap-space-xs flex-wrap">
            <button
              type="button"
              aria-label="All"
              onClick={() => setSelectedRisk('ALL')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-all ${
                selectedRisk === 'ALL'
                  ? 'bg-on-surface text-surface font-bold shadow-sm'
                  : 'bg-surface-container-low text-on-surface-variant hover:bg-surface-container font-medium'
              }`}
            >
              <span>All</span>
              <span className="font-mono text-[10px] px-1 rounded bg-surface/20">{counts.ALL}</span>
            </button>

            <button
              type="button"
              aria-label="Critical"
              onClick={() => setSelectedRisk('CRITICAL')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-all ${
                selectedRisk === 'CRITICAL'
                  ? 'bg-error-container text-on-error-container font-bold ring-2 ring-error'
                  : 'bg-error-container/60 text-on-error-container hover:bg-error-container'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-error"></span>
              <span>Critical</span>
              <span className="font-mono text-[10px] font-bold">{counts.CRITICAL}</span>
            </button>

            <button
              type="button"
              aria-label="High"
              onClick={() => setSelectedRisk('HIGH')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-all ${
                selectedRisk === 'HIGH'
                  ? 'bg-[#fed7aa] text-[#9a3412] font-bold ring-2 ring-[#f97316]'
                  : 'bg-[#fed7aa]/60 text-[#9a3412] hover:bg-[#fed7aa]'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[#f97316]"></span>
              <span>High</span>
              <span className="font-mono text-[10px] font-bold">{counts.HIGH}</span>
            </button>

            <button
              type="button"
              onClick={() => setSelectedRisk('MEDIUM')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-all ${
                selectedRisk === 'MEDIUM'
                  ? 'bg-[#fef08a] text-[#854d0e] font-bold ring-2 ring-[#eab308]'
                  : 'bg-[#fef08a]/60 text-[#854d0e] hover:bg-[#fef08a]'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[#eab308]"></span>
              <span>Medium</span>
              <span className="font-mono text-[10px] font-bold">{counts.MEDIUM}</span>
            </button>

            <button
              type="button"
              onClick={() => setSelectedRisk('INFO')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-all ${
                selectedRisk === 'INFO'
                  ? 'bg-[#bbf7d0] text-[#166534] font-bold ring-2 ring-[#16a34a]'
                  : 'bg-[#bbf7d0]/60 text-[#166534] hover:bg-[#bbf7d0]'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[#16a34a]"></span>
              <span>Clean</span>
              <span className="font-mono text-[10px] font-bold">{counts.INFO}</span>
            </button>
          </div>

          {/* Tag Quick Filters */}
          <div className="flex items-center gap-space-xs text-xs">
            <button
              onClick={() => setSelectedTag(selectedTag === 'EXPOSED_PORTS' ? '' : 'EXPOSED_PORTS')}
              className={`px-2 py-1 rounded transition-colors ${
                selectedTag === 'EXPOSED_PORTS'
                  ? 'bg-error-container text-on-error-container font-semibold'
                  : 'bg-surface-container-low text-secondary hover:bg-surface-container'
              }`}
            >
              Exposed Management Ports
            </button>
            <button
              onClick={() => setSelectedTag(selectedTag === 'EXPIRED_SSL' ? '' : 'EXPIRED_SSL')}
              className={`px-2 py-1 rounded transition-colors ${
                selectedTag === 'EXPIRED_SSL'
                  ? 'bg-[#fed7aa] text-[#9a3412] font-semibold'
                  : 'bg-surface-container-low text-secondary hover:bg-surface-container'
              }`}
            >
              Expired SSL
            </button>
          </div>
        </div>
      </div>

      {/* High Density Table */}
      <div className="bg-surface-container-lowest rounded-xl shadow-sm border border-surface-variant/40 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-surface-container-low text-secondary uppercase tracking-wider font-semibold border-b border-surface-variant">
                <th className="py-2.5 px-4">Hostname & Apex</th>
                <th className="py-2.5 px-3">IP & ASN</th>
                <th className="py-2.5 px-3">Open Ports</th>
                <th className="py-2.5 px-3">Detected Technologies</th>
                <th className="py-2.5 px-3 text-center">Header Grade</th>
                <th className="py-2.5 px-3 text-right">Risk Score</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container">
              {filteredAssets.map((asset) => {
                const isCriticalPort = asset.open_ports?.some((p) => [3389, 445, 23, 27017].includes(p));
                return (
                  <tr
                    key={asset.id}
                    onClick={() => onSelectAsset && onSelectAsset(asset)}
                    className="hover:bg-surface-container-low/70 transition-colors cursor-pointer group"
                  >
                    {/* Hostname */}
                    <td className="py-3 px-4 font-mono">
                      <div className="flex items-center gap-1.5">
                        <span className="font-bold text-on-surface group-hover:text-primary transition-colors">
                          {asset.hostname}
                        </span>
                        {asset.is_apex && (
                          <span className="text-[10px] px-1 py-0.2 rounded bg-surface-container text-secondary">
                            APEX
                          </span>
                        )}
                      </div>
                    </td>

                    {/* IP & ASN */}
                    <td className="py-3 px-3 font-mono text-secondary">
                      <div>{asset.ip_address || '—'}</div>
                      <div className="text-[10px] text-outline truncate max-w-[140px]">{asset.asn || 'AS13335 Cloudflare'}</div>
                    </td>

                    {/* Ports */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1 flex-wrap max-w-[180px]">
                        {asset.open_ports?.length > 0 ? (
                          asset.open_ports.slice(0, 4).map((p) => (
                            <span
                              key={p}
                              className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold ${
                                [3389, 445, 27017, 23].includes(p)
                                  ? 'bg-error-container text-on-error-container'
                                  : 'bg-surface-container-low text-on-surface'
                              }`}
                            >
                              {p}
                            </span>
                          ))
                        ) : (
                          <span className="text-secondary text-[11px]">—</span>
                        )}
                        {asset.open_ports?.length > 4 && (
                          <span className="text-[10px] text-outline font-mono">+{asset.open_ports.length - 4}</span>
                        )}
                      </div>
                    </td>

                    {/* Tech Stack */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1 flex-wrap max-w-[200px]">
                        {asset.technologies?.length > 0 ? (
                          asset.technologies.slice(0, 3).map((t) => (
                            <span
                              key={t}
                              className="px-1.5 py-0.5 rounded bg-surface-container text-secondary text-[10px] truncate max-w-[90px]"
                            >
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-secondary text-[11px]">—</span>
                        )}
                      </div>
                    </td>

                    {/* Header Grade */}
                    <td className="py-3 px-3 text-center">
                      <span
                        className={`inline-block w-6 h-6 leading-6 text-center rounded font-mono text-xs font-bold ${
                          asset.header_grade === 'A' || asset.header_grade === 'A+'
                            ? 'bg-[#dcfce7] text-[#166534]'
                            : asset.header_grade === 'B' || asset.header_grade === 'C'
                            ? 'bg-[#fef08a] text-[#854d0e]'
                            : 'bg-error-container text-on-error-container'
                        }`}
                      >
                        {asset.header_grade || 'F'}
                      </span>
                    </td>

                    {/* Risk Score */}
                    <td className="py-3 px-3 text-right">
                      <div className="flex flex-col items-end">
                        <span
                          className={`inline-block px-1.5 py-0.5 rounded text-[11px] font-mono font-bold ${
                            asset.risk_score >= 80
                              ? 'bg-error-container text-on-error-container'
                              : asset.risk_score >= 60
                              ? 'bg-[#fed7aa] text-[#9a3412]'
                              : asset.risk_score >= 40
                              ? 'bg-[#fef08a] text-[#854d0e]'
                              : 'bg-[#dcfce7] text-[#166534]'
                          }`}
                        >
                          {asset.risk_score?.toFixed(1) || '0.0'}
                        </span>
                        <span className="text-[9px] uppercase tracking-wider text-outline mt-0.5">
                          {asset.risk_level || 'info'}
                        </span>
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAsset && onSelectAsset(asset);
                        }}
                        className="inline-flex items-center gap-0.5 text-xs text-primary font-semibold hover:underline"
                      >
                        <span>Inspect</span>
                        <span className="material-symbols-outlined text-[16px]">chevron_right</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function getMockAssets() {
  return [
    {
      id: 'ast-1',
      hostname: 'vpn-stage.example.com',
      ip_address: '198.51.100.42',
      is_apex: false,
      risk_score: 94.2,
      risk_level: 'critical',
      open_ports: [80, 443, 3389],
      technologies: ['Apache 2.4.49', 'OpenSSL 1.0.2', 'PHP 7.4'],
      header_grade: 'F',
      asn: 'AS16509 AWS',
      ssl_status: 'expired',
      shap_explanation: {
        base_score: 20.0,
        features: [
          { name: 'Exposed RDP Port (3389)', weight: 35.0, type: 'risk' },
          { name: 'Expired SSL Certificate', weight: 18.5, type: 'risk' },
          { name: 'Missing CSP & HSTS Headers', weight: 12.0, type: 'risk' },
          { name: 'CVE-2021-41773 (Path Traversal)', weight: 9.0, type: 'risk' },
          { name: 'Active Cloudflare Offset', weight: -0.3, type: 'benefit' },
        ],
      },
    },
    {
      id: 'ast-2',
      hostname: 'dev-db.example.com',
      ip_address: '198.51.100.55',
      is_apex: false,
      risk_score: 88.0,
      risk_level: 'critical',
      open_ports: [22, 27017],
      technologies: ['MongoDB 5.0', 'OpenSSH 8.2'],
      header_grade: 'F',
      asn: 'AS16509 AWS',
      ssl_status: 'self-signed',
      shap_explanation: {
        base_score: 20.0,
        features: [
          { name: 'Exposed Database (MongoDB 27017)', weight: 42.0, type: 'risk' },
          { name: 'Public SSH Port (22)', weight: 16.0, type: 'risk' },
          { name: 'Missing Perimeter Firewall', weight: 10.0, type: 'risk' },
        ],
      },
    },
    {
      id: 'ast-3',
      hostname: 'billing-api.example.com',
      ip_address: '198.51.100.89',
      is_apex: false,
      risk_score: 79.5,
      risk_level: 'high',
      open_ports: [80, 443],
      technologies: ['Node.js', 'Express', 'Nginx 1.18'],
      header_grade: 'C',
      asn: 'AS13335 Cloudflare',
      ssl_status: 'valid',
      shap_explanation: {
        base_score: 20.0,
        features: [
          { name: 'Outdated Nginx 1.18 Web Server', weight: 24.5, type: 'risk' },
          { name: 'Missing HSTS Directive', weight: 18.0, type: 'risk' },
          { name: 'Cloudflare WAF Ingress Defense', weight: -6.0, type: 'benefit' },
        ],
      },
    },
    {
      id: 'ast-4',
      hostname: 'auth.example.com',
      ip_address: '198.51.100.12',
      is_apex: false,
      risk_score: 71.0,
      risk_level: 'high',
      open_ports: [443, 8443],
      technologies: ['Keycloak 20', 'Java 17'],
      header_grade: 'B',
      asn: 'AS13335 Cloudflare',
      ssl_status: 'valid',
    },
    {
      id: 'ast-5',
      hostname: 'example.com',
      ip_address: '93.184.216.34',
      is_apex: true,
      risk_score: 24.0,
      risk_level: 'low',
      open_ports: [80, 443],
      technologies: ['Cloudflare Edge', 'HSTS Enabled'],
      header_grade: 'A',
      asn: 'AS15133 EdgeCast',
      ssl_status: 'valid',
    },
    {
      id: 'ast-6',
      hostname: 'cdn.example.com',
      ip_address: '104.21.45.12',
      is_apex: false,
      risk_score: 12.5,
      risk_level: 'info',
      open_ports: [443],
      technologies: ['Cloudflare CDN'],
      header_grade: 'A+',
      asn: 'AS13335 Cloudflare',
      ssl_status: 'valid',
    },
  ];
}
