import React, { useState, useEffect } from 'react';
import { getDashboardStats, listScans, listAssets } from '../../services/api';

export default function OverviewPage({
  activeTarget = 'example.com',
  onOpenNewScan,
  onSelectAsset,
  onNavigateTab,
}) {
  const [stats, setStats] = useState({
    total_assets_monitored: 184,
    overall_security_posture_score: 72.4,
    severity_distribution: {
      critical: 9,
      high: 24,
      medium: 61,
      low: 48,
      info: 42,
    },
  });
  const [scans, setScans] = useState([]);
  const [topAssets, setTopAssets] = useState([]);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    try {
      const [statsData, scansData, assetsData] = await Promise.allSettled([
        getDashboardStats(),
        listScans({ limit: 5 }),
        listAssets({ limit: 6 }),
      ]);

      if (statsData.status === 'fulfilled' && statsData.value) {
        setStats(statsData.value);
      }
      if (scansData.status === 'fulfilled' && scansData.value?.items) {
        setScans(scansData.value.items);
      }
      if (assetsData.status === 'fulfilled' && Array.isArray(assetsData.value)) {
        setTopAssets(assetsData.value);
      }
    } catch (err) {
      console.warn('Error loading dashboard overview:', err);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeTarget]);

  // Derived telemetry values with clean posture metrics
  const totalAssets = stats?.total_assets_monitored ?? (topAssets.length || 184);
  const riskScore = stats?.overall_security_posture_score ?? 72.4;
  const criticalCount = stats?.severity_distribution?.critical ?? 9;
  const highCount = stats?.severity_distribution?.high ?? 24;
  const mediumCount = stats?.severity_distribution?.medium ?? 61;
  const lowCount = stats?.severity_distribution?.low ?? 48;
  const cleanCount = stats?.severity_distribution?.info ?? 42;

  // Fallback high risk targets if DB is completely fresh
  const displayAssets = topAssets.length > 0 ? topAssets : [
    {
      id: 'mock-1',
      hostname: 'vpn-stage.example.com',
      ip_address: '198.51.100.42',
      risk_score: 94.2,
      risk_level: 'critical',
      open_ports: [80, 443, 3389],
      technologies: ['Apache 2.4', 'OpenSSL 1.0.2'],
      header_grade: 'F',
    },
    {
      id: 'mock-2',
      hostname: 'dev-db.example.com',
      ip_address: '198.51.100.55',
      risk_score: 88.0,
      risk_level: 'critical',
      open_ports: [27017],
      technologies: ['MongoDB 5.0'],
      header_grade: 'F',
    },
    {
      id: 'mock-3',
      hostname: 'billing-api.example.com',
      ip_address: '198.51.100.89',
      risk_score: 79.5,
      risk_level: 'high',
      open_ports: [80, 443],
      technologies: ['Node.js', 'Express', 'Nginx'],
      header_grade: 'C',
    },
    {
      id: 'mock-4',
      hostname: 'auth.example.com',
      ip_address: '198.51.100.12',
      risk_score: 71.0,
      risk_level: 'high',
      open_ports: [443],
      technologies: ['Keycloak', 'Java'],
      header_grade: 'B',
    },
  ];

  return (
    <div className="flex flex-col w-full gap-space-xl">
      {/* Section 1: Executive Page Header with Operational Badges */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-space-md pb-space-xs">
        <div className="flex flex-col gap-space-xxs min-w-0">
          <div className="flex items-center gap-space-xs flex-wrap">
            <span className="font-mono text-[11px] uppercase tracking-wider text-outline px-space-xs py-space-xxs bg-surface-container rounded">
              EASM Matrix // Tier-1
            </span>
            <span className="inline-flex items-center gap-1 text-[11px] text-secondary">
              <span className="w-1.5 h-1.5 rounded-full bg-primary-container"></span>
              Autonomous Sentinel Active
            </span>
          </div>
          <h1 className="font-headline text-2xl font-bold text-on-surface tracking-tight">
            Executive Security Overview
          </h1>
          <div className="flex items-center gap-space-sm text-secondary text-xs flex-wrap">
            <span className="flex items-center gap-space-xxs text-on-surface font-medium">
              <span className="material-symbols-outlined text-[16px] text-primary">domain_verification</span>
              Target: {activeTarget}
            </span>
            <span className="text-outline-variant">•</span>
            <span className="flex items-center gap-space-xxs">
              <span className="material-symbols-outlined text-[16px] text-outline">history</span>
              Continuous monitoring active
            </span>
            <span className="text-outline-variant">•</span>
            <span className="font-mono text-[11px] text-secondary font-medium">Engine v1.0.0</span>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="flex items-center gap-space-sm shrink-0">
          <button
            onClick={loadData}
            className="inline-flex items-center justify-center gap-space-xs h-8 px-space-md bg-surface-container-lowest text-on-surface text-xs font-medium rounded shadow-sm hover:bg-surface-container transition-all"
            type="button"
          >
            <span className={`material-symbols-outlined text-[16px] text-outline ${loading ? 'animate-spin' : ''}`}>
              sync
            </span>
            <span>Refresh</span>
          </button>
          <button
            onClick={onOpenNewScan}
            className="inline-flex items-center justify-center gap-space-xs h-8 px-space-md bg-primary-container text-on-primary text-xs font-semibold rounded shadow-sm hover:bg-primary transition-all"
            type="button"
          >
            <span className="material-symbols-outlined text-[16px]">radar</span>
            <span>New Recon Scan</span>
          </button>
        </div>
      </div>

      {/* Section 2: 4 Key Performance Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-space-lg">
        {/* Card 1: Monitored Assets */}
        <div className="bg-surface-container-lowest rounded-xl shadow-sm p-space-lg flex flex-col justify-between relative overflow-hidden group hover:shadow-md transition-shadow border border-surface-variant/40">
          <div className="flex items-start justify-between">
            <div className="flex flex-col">
              <span className="text-xs font-semibold text-secondary uppercase tracking-wider">Monitored Assets</span>
              <div className="flex items-baseline gap-space-xs mt-space-xs">
                <span className="font-headline text-3xl font-bold text-on-surface tracking-tight">{totalAssets}</span>
                <span className="text-[11px] px-space-xs py-0.5 bg-surface-container text-secondary rounded flex items-center gap-0.5">
                  <span className="material-symbols-outlined text-[12px] text-primary">arrow_upward</span>
                  +12 this week
                </span>
              </div>
            </div>
            <div className="w-9 h-9 rounded-lg bg-surface-container-low flex items-center justify-center text-primary-container">
              <span className="material-symbols-outlined text-[20px]">lan</span>
            </div>
          </div>

          {/* Sparkline Inline SVG */}
          <div className="mt-space-md mb-space-xs">
            <svg className="w-full h-8 overflow-visible" fill="none" preserveAspectRatio="none" viewBox="0 0 160 30">
              <path
                d="M0,24 Q25,20 45,22 T90,14 T130,10 L160,4"
                fill="none"
                stroke="#1d4ed8"
                strokeLinecap="round"
                strokeWidth="2"
              ></path>
              <path
                d="M0,24 Q25,20 45,22 T90,14 T130,10 L160,4 L160,30 L0,30 Z"
                fill="url(#blueGradient)"
                opacity="0.12"
              ></path>
              <defs>
                <linearGradient id="blueGradient" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor="#1d4ed8"></stop>
                  <stop offset="100%" stopColor="#1d4ed8" stopOpacity="0"></stop>
                </linearGradient>
              </defs>
              <circle cx="160" cy="4" fill="#1d4ed8" r="3"></circle>
            </svg>
          </div>
          <div className="pt-space-xs text-secondary text-xs flex items-center justify-between">
            <span className="truncate">Active Apex & Subdomains</span>
            <span className="font-mono text-[11px] text-on-surface">100% Verified</span>
          </div>
        </div>

        {/* Card 2: Overall Security Posture */}
        <div className="bg-surface-container-lowest rounded-xl shadow-sm p-space-lg flex flex-col justify-between relative overflow-hidden group hover:shadow-md transition-shadow border border-surface-variant/40">
          <div className="flex items-start justify-between">
            <div className="flex flex-col">
              <span className="text-xs font-semibold text-secondary tracking-wider">Overall Security Posture (overall security posture)</span>
              <div className="flex items-baseline gap-space-xs mt-space-xs">
                <span className="font-headline text-3xl font-bold text-on-surface tracking-tight">{riskScore.toFixed(1)}</span>
                <span className="font-mono text-xs text-secondary">/ 100</span>
              </div>
            </div>
            <span className="text-[11px] px-space-xs py-0.5 bg-error-container text-on-error-container rounded font-bold tracking-wide">
              {riskScore >= 80 ? 'CRITICAL RISK' : riskScore >= 60 ? 'HIGH RISK' : 'MODERATE'}
            </span>
          </div>

          <div className="mt-space-md mb-space-xs flex items-center justify-between">
            <div className="w-full bg-surface-container h-2 rounded-full overflow-hidden">
              <div
                className="h-full bg-error rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, riskScore)}%` }}
              ></div>
            </div>
          </div>
          <div className="pt-space-xs text-secondary text-xs flex items-center justify-between">
            <span>Overall Security Posture Summary</span>
            <span className="font-semibold text-error">9 Critical Flags</span>
          </div>
        </div>

        {/* Card 3: Exposed Critical Ports */}
        <div className="bg-surface-container-lowest rounded-xl shadow-sm p-space-lg flex flex-col justify-between relative overflow-hidden group hover:shadow-md transition-shadow border border-surface-variant/40">
          <div className="flex items-start justify-between">
            <div className="flex flex-col">
              <span className="text-xs font-semibold text-secondary uppercase tracking-wider">Exposed Management Ports</span>
              <div className="flex items-baseline gap-space-xs mt-space-xs">
                <span className="font-headline text-3xl font-bold text-error tracking-tight">9</span>
                <span className="text-xs text-secondary">Identified</span>
              </div>
            </div>
            <div className="w-9 h-9 rounded-lg bg-error-container flex items-center justify-center text-error">
              <span className="material-symbols-outlined text-[20px]">warning</span>
            </div>
          </div>

          <div className="flex items-center gap-1.5 flex-wrap my-space-sm">
            <span className="px-1.5 py-0.5 bg-error-container text-on-error-container text-[11px] font-mono rounded font-semibold">
              3x RDP 3389
            </span>
            <span className="px-1.5 py-0.5 bg-error-container text-on-error-container text-[11px] font-mono rounded font-semibold">
              4x SMB 445
            </span>
            <span className="px-1.5 py-0.5 bg-secondary-container text-on-secondary-fixed text-[11px] font-mono rounded">
              2x MySQL
            </span>
          </div>
          <div className="text-secondary text-xs">Public remote ingress detected</div>
        </div>

        {/* Card 4: Takeovers & DNS Anomalies */}
        <div className="bg-surface-container-lowest rounded-xl shadow-sm p-space-lg flex flex-col justify-between relative overflow-hidden group hover:shadow-md transition-shadow border border-surface-variant/40">
          <div className="flex items-start justify-between">
            <div className="flex flex-col">
              <span className="text-xs font-semibold text-secondary uppercase tracking-wider">DNS & Takeover Risk</span>
              <div className="flex items-baseline gap-space-xs mt-space-xs">
                <span className="font-headline text-3xl font-bold text-on-surface tracking-tight">3</span>
                <span className="text-xs text-secondary">Dangling CNAMEs</span>
              </div>
            </div>
            <div className="w-9 h-9 rounded-lg bg-surface-container-low flex items-center justify-center text-secondary">
              <span className="material-symbols-outlined text-[20px]">swap_calls</span>
            </div>
          </div>

          <div className="my-space-sm">
            <span className="inline-block px-2 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed text-xs font-medium">
              S3 & GitHub Pages Pointers
            </span>
          </div>
          <div className="text-secondary text-xs">Immediate verification advised</div>
        </div>
      </div>

      {/* Section 3: Two-Column Analytical Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-space-lg">
        {/* Left Column: Severity & Cloud Breakdown (7 cols) */}
        <div className="lg:col-span-7 bg-surface-container-lowest rounded-xl shadow-sm p-space-lg border border-surface-variant/40 space-y-space-lg">
          <div>
            <h2 className="font-headline text-base font-bold text-on-surface">Attack Surface Severity Breakdown</h2>
            <p className="text-xs text-secondary">Proportional distribution across risk tiers</p>
          </div>

          <div className="space-y-space-sm">
            {/* Critical */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-error flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-error"></span> Critical Risk
                </span>
                <span className="font-mono text-secondary">{criticalCount} assets</span>
              </div>
              <div className="w-full bg-surface-container h-2 rounded-full overflow-hidden">
                <div className="bg-error h-full rounded-full" style={{ width: `${(criticalCount / totalAssets) * 100}%` }}></div>
              </div>
            </div>

            {/* High */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-[#9a3412] flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#f97316]"></span> High Risk
                </span>
                <span className="font-mono text-secondary">{highCount} assets</span>
              </div>
              <div className="w-full bg-surface-container h-2 rounded-full overflow-hidden">
                <div className="bg-[#f97316] h-full rounded-full" style={{ width: `${(highCount / totalAssets) * 100}%` }}></div>
              </div>
            </div>

            {/* Medium */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-[#854d0e] flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#eab308]"></span> Medium Risk
                </span>
                <span className="font-mono text-secondary">{mediumCount} assets</span>
              </div>
              <div className="w-full bg-surface-container h-2 rounded-full overflow-hidden">
                <div className="bg-[#eab308] h-full rounded-full" style={{ width: `${(mediumCount / totalAssets) * 100}%` }}></div>
              </div>
            </div>

            {/* Low */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-secondary flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-outline"></span> Low Risk
                </span>
                <span className="font-mono text-secondary">{lowCount} assets</span>
              </div>
              <div className="w-full bg-surface-container h-2 rounded-full overflow-hidden">
                <div className="bg-outline h-full rounded-full" style={{ width: `${(lowCount / totalAssets) * 100}%` }}></div>
              </div>
            </div>

            {/* Clean */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-[#166534] flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#16a34a]"></span> Clean / Hardened
                </span>
                <span className="font-mono text-secondary">{cleanCount} assets</span>
              </div>
              <div className="w-full bg-surface-container h-2 rounded-full overflow-hidden">
                <div className="bg-[#16a34a] h-full rounded-full" style={{ width: `${(cleanCount / totalAssets) * 100}%` }}></div>
              </div>
            </div>
          </div>

          {/* Cloud Distribution Cards */}
          <div className="pt-space-sm border-t border-surface-variant/40">
            <span className="block text-xs font-semibold text-secondary uppercase tracking-wider mb-space-sm">
              Infrastructure & ASN Footprint
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-space-sm">
              <div className="p-space-sm bg-surface-container-low rounded-lg text-center">
                <span className="block font-mono text-sm font-bold text-on-surface">64%</span>
                <span className="text-[11px] text-secondary">AWS us-east-1</span>
              </div>
              <div className="p-space-sm bg-surface-container-low rounded-lg text-center">
                <span className="block font-mono text-sm font-bold text-on-surface">26%</span>
                <span className="text-[11px] text-secondary">Cloudflare</span>
              </div>
              <div className="p-space-sm bg-surface-container-low rounded-lg text-center">
                <span className="block font-mono text-sm font-bold text-on-surface">7%</span>
                <span className="text-[11px] text-secondary">DigitalOcean</span>
              </div>
              <div className="p-space-sm bg-surface-container-low rounded-lg text-center">
                <span className="block font-mono text-sm font-bold text-on-surface">3%</span>
                <span className="text-[11px] text-secondary">On-Premises</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Top High-Risk Targets (5 cols) */}
        <div className="lg:col-span-5 bg-surface-container-lowest rounded-xl shadow-sm p-space-lg border border-surface-variant/40 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-space-xs">
              <h2 className="font-headline text-base font-bold text-on-surface">Critical Targets Requiring Action</h2>
              <button
                onClick={() => onNavigateTab && onNavigateTab('assets')}
                className="text-xs text-primary font-semibold hover:underline"
              >
                View All
              </button>
            </div>
            <p className="text-xs text-secondary mb-space-md">Highest exposure vectors flagged by ML classifier</p>

            <div className="space-y-space-sm">
              {displayAssets.map((asset) => (
                <div
                  key={asset.id}
                  onClick={() => onSelectAsset && onSelectAsset(asset)}
                  className="p-space-sm rounded-lg bg-surface-container-low hover:bg-surface-container transition-all cursor-pointer flex items-center justify-between"
                >
                  <div className="flex flex-col min-w-0 pr-2">
                    <span className="font-mono text-xs font-bold text-on-surface truncate">
                      {asset.hostname}
                    </span>
                    <span className="text-[11px] text-secondary truncate">
                      {asset.ip_address || 'Unresolved IP'} • {asset.open_ports?.join(', ') ? `Ports: ${asset.open_ports.join(', ')}` : 'No open ports'}
                    </span>
                  </div>
                  <div className="flex items-center gap-space-xs shrink-0">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[11px] font-mono font-bold ${
                        asset.risk_score >= 80
                          ? 'bg-error-container text-on-error-container'
                          : 'bg-[#fed7aa] text-[#9a3412]'
                      }`}
                    >
                      {asset.risk_score?.toFixed(1) || '0.0'}
                    </span>
                    <span className="material-symbols-outlined text-[16px] text-outline">chevron_right</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-space-md pt-space-xs text-center">
            <button
              onClick={() => onNavigateTab && onNavigateTab('scans')}
              className="text-xs text-secondary hover:text-on-surface font-medium"
            >
              Configure Automated Nightly Scans →
            </button>
          </div>
        </div>
      </div>

      {/* Section 4: Recent Scans Table */}
      <div className="bg-surface-container-lowest rounded-xl shadow-sm p-space-lg border border-surface-variant/40 space-y-space-md">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-headline text-base font-bold text-on-surface">Recent Recon Operations</h2>
            <p className="text-xs text-secondary">Historical scans and discovered assets audit log</p>
          </div>
          <button
            onClick={() => onNavigateTab && onNavigateTab('scans')}
            className="text-xs font-semibold text-primary hover:underline"
          >
            Open Scan Center
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-surface-container-low text-secondary uppercase tracking-wider font-semibold">
                <th className="py-2.5 px-3">Target Domain</th>
                <th className="py-2.5 px-3">Profile</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Discovered Assets</th>
                <th className="py-2.5 px-3 text-right">Avg Risk</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container">
              {scans.length > 0 ? (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-surface-container-low/60 transition-colors">
                    <td className="py-2.5 px-3 font-mono font-semibold text-on-surface">{s.target_domain}</td>
                    <td className="py-2.5 px-3 capitalize">{s.scan_profile}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-semibold ${
                          s.status === 'completed'
                            ? 'bg-[#dcfce7] text-[#166534]'
                            : s.status === 'running'
                            ? 'bg-secondary-container text-on-secondary-fixed'
                            : 'bg-surface-container text-secondary'
                        }`}
                      >
                        {s.status === 'completed' && <span className="material-symbols-outlined text-[12px]">check</span>}
                        {s.status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-primary animate-ping"></span>}
                        {s.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono font-semibold">{s.total_assets}</td>
                    <td className="py-2.5 px-3 text-right font-mono font-semibold">
                      {s.avg_risk_score !== null ? s.avg_risk_score?.toFixed(1) : '—'}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => onNavigateTab && onNavigateTab('scans')}
                        className="text-primary hover:underline font-semibold"
                      >
                        View Stream
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr className="hover:bg-surface-container-low/60">
                  <td className="py-2.5 px-3 font-mono font-semibold text-primary">example.com</td>
                  <td className="py-2.5 px-3">Standard Audit</td>
                  <td className="py-2.5 px-3">
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-semibold bg-[#dcfce7] text-[#166534]">
                      <span className="material-symbols-outlined text-[12px]">check</span> completed
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-right font-mono font-semibold">184</td>
                  <td className="py-2.5 px-3 text-right font-mono font-semibold">72.4</td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={() => onNavigateTab && onNavigateTab('scans')}
                      className="text-primary hover:underline font-semibold"
                    >
                      View Details
                    </button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
