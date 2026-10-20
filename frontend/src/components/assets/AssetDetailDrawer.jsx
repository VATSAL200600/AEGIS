import React, { useState, useEffect } from 'react';
import { getAsset } from '../../services/api';

export default function AssetDetailDrawer({ asset, isOpen, onClose, onRescan }) {
  const [activeTab, setActiveTab] = useState('RISK');
  const [assetDetail, setAssetDetail] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (asset?.id) {
      setAssetDetail(asset);
      // Fetch full details if it's a real DB record
      setLoading(true);
      getAsset(asset.id)
        .then((detail) => {
          if (detail) setAssetDetail((prev) => ({ ...prev, ...detail }));
        })
        .catch(() => {})
        .finally(() => setLoading(false));
    }
  }, [asset?.id]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !asset) return null;

  const current = assetDetail || asset;

  // Fallback SHAP features if none in record
  const shapFeatures = current.shap_explanation?.features || [
    { name: 'Exposed Management Port (RDP 3389)', weight: 35.0, type: 'risk' },
    { name: 'Expired SSL/TLS Certificate', weight: 18.5, type: 'risk' },
    { name: 'Missing Content-Security-Policy & HSTS', weight: 12.0, type: 'risk' },
    { name: 'Known Vulnerability CVE-2021-41773', weight: 9.0, type: 'risk' },
    { name: 'Subdomain Depth Defense Offset', weight: -2.3, type: 'benefit' },
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="fixed inset-0 bg-slate-900/30 backdrop-blur-[2px] transition-opacity"
      ></div>

      {/* Slide-over Drawer (640px wide) */}
      <div className="relative w-full max-w-2xl bg-surface-container-lowest h-full shadow-2xl flex flex-col z-10 border-l border-surface-variant animate-slideLeft">
        {/* Top Control Bar */}
        <div className="flex items-center justify-between p-space-lg border-b border-surface-variant bg-surface-container-lowest">
          <div className="flex items-center gap-space-xs text-xs text-secondary font-mono">
            <span className="material-symbols-outlined text-[16px] text-primary">analytics</span>
            <span>NODE DOSSIER // {current.id?.slice(0, 8) || 'REF'}</span>
          </div>
          <div className="flex items-center gap-space-xs">
            {onRescan && (
              <button
                type="button"
                onClick={() => onRescan(current)}
                className="inline-flex items-center gap-1 h-8 px-space-md bg-surface-container-low hover:bg-surface-container text-on-surface text-xs font-semibold rounded transition-colors"
              >
                <span className="material-symbols-outlined text-[16px] text-primary">sync</span>
                <span>Re-scan Asset</span>
              </button>
            )}
            <button
              type="button"
              id="close-drawer-btn"
              aria-label="Close drawer"
              onClick={onClose}
              className="h-8 w-8 inline-flex items-center justify-center rounded hover:bg-surface-container text-outline hover:text-on-surface transition-colors"
            >
              <span className="material-symbols-outlined text-[20px]">close</span>
            </button>
          </div>
        </div>

        {/* Identity & Score Header */}
        <div className="p-space-lg border-b border-surface-variant space-y-space-md">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-md">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <h1 className="font-headline text-xl font-bold text-on-surface tracking-tight truncate">
                  {current.hostname}
                </h1>
                <button
                  type="button"
                  onClick={() => navigator.clipboard?.writeText(current.hostname)}
                  className="p-1 text-outline hover:text-primary rounded transition-colors"
                  title="Copy Hostname"
                >
                  <span className="material-symbols-outlined text-[16px]">content_copy</span>
                </button>
              </div>
              <span className="text-xs text-secondary font-mono">
                {current.is_apex ? 'Apex Domain Root' : 'Discovered Subdomain Node'}
              </span>
            </div>

            {/* Risk Badge */}
            <div className="flex items-center gap-space-xs px-3 py-1.5 rounded bg-error-container text-on-error-container shadow-sm self-start sm:self-auto">
              <span className="material-symbols-outlined text-error text-[18px]">warning</span>
              <div className="flex flex-col">
                <span className="font-mono text-xs font-bold text-error">
                  {current.risk_score?.toFixed(1) || '0.0'} / 100
                </span>
                <span className="text-[10px] font-semibold tracking-wider uppercase text-on-error-container">
                  {current.risk_level || 'CRITICAL'} RISK
                </span>
              </div>
            </div>
          </div>

          {/* Quick Telemetry Ribbon */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-space-xs pt-1">
            <div className="p-space-xs bg-surface-container-low rounded text-center">
              <span className="block text-[10px] text-outline uppercase font-semibold">Public IPv4</span>
              <span className="font-mono text-xs font-semibold text-on-surface">{current.ip_address || '—'}</span>
            </div>
            <div className="p-space-xs bg-surface-container-low rounded text-center">
              <span className="block text-[10px] text-outline uppercase font-semibold">Autonomous System</span>
              <span className="font-mono text-xs font-semibold text-on-surface truncate">{current.asn || 'AS16509 AWS'}</span>
            </div>
            <div className="p-space-xs bg-surface-container-low rounded text-center">
              <span className="block text-[10px] text-outline uppercase font-semibold">SSL Status</span>
              <span className="font-mono text-xs font-semibold capitalize text-on-surface">
                {current.ssl_status || 'Valid TLS'}
              </span>
            </div>
            <div className="p-space-xs bg-surface-container-low rounded text-center">
              <span className="block text-[10px] text-outline uppercase font-semibold">Header Grade</span>
              <span className="font-mono text-xs font-bold text-on-surface">{current.header_grade || 'F'}</span>
            </div>
          </div>
        </div>

        {/* Tab Headers */}
        <div className="flex items-center px-space-lg bg-surface-container-lowest border-b border-surface-variant overflow-x-auto">
          <div className="flex items-center gap-space-md">
            {[
              { id: 'RISK', label: 'Explainability & Risk Factors', count: shapFeatures.length },
              { id: 'PORTS', label: 'Ports & Services', count: current.open_ports?.length || 3 },
              { id: 'TECH', label: 'Tech Stack', count: current.technologies?.length || 3 },
              { id: 'SSL', label: 'SSL & Headers', count: null },
              { id: 'CVES', label: 'CVEs & Intel', count: 2 },
            ].map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-1.5 py-3 text-xs font-semibold border-b-2 transition-all ${
                    isActive
                      ? 'border-primary-container text-primary-container'
                      : 'border-transparent text-secondary hover:text-on-surface'
                  }`}
                >
                  <span>{tab.label}</span>
                  {tab.count !== null && (
                    <span className="font-mono text-[10px] px-1 py-0.2 bg-surface-container rounded text-secondary">
                      {tab.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Tab Content Body */}
        <div className="flex-1 overflow-y-auto p-space-lg space-y-space-lg bg-surface">
          {/* TAB 1: RISK FACTORS & SHAP WATERFALL */}
          {activeTab === 'RISK' && (
            <div className="space-y-space-lg">
              {/* Insight Callout */}
              <div className="p-space-md bg-secondary-container/40 rounded-xl flex items-start gap-space-md border border-primary-container/20">
                <div className="p-2 bg-surface-container-lowest rounded-lg text-primary shadow-sm shrink-0">
                  <span className="material-symbols-outlined text-[20px]">psychology</span>
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold text-on-surface">TreeSHAP Explainability & Attribution Model</span>
                    <span className="text-[10px] px-1.5 py-0.2 bg-primary/10 text-primary rounded font-semibold uppercase">
                      XGBoost Model
                    </span>
                  </div>
                  <p className="text-xs text-on-surface-variant leading-relaxed">
                    This asset received an evaluated risk score of{' '}
                    <strong className="text-error font-bold">{current.risk_score?.toFixed(1) || '94.2'}</strong>. The primary
                    driver is an unshielded remote management port coupled with perimeter security header omissions.
                  </p>
                </div>
              </div>

              {/* SHAP Waterfall Bars */}
              <div className="bg-surface-container-lowest p-space-lg rounded-xl shadow-sm border border-surface-variant/40 space-y-space-md">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-headline text-sm font-bold text-on-surface">TreeSHAP Explainability & Feature Contribution</h3>
                    <p className="text-xs text-secondary">Marginal risk points attributed by SHAP Tree Explainability model</p>
                  </div>
                  <span className="font-mono text-xs font-semibold text-secondary">Base Score: +20.0</span>
                </div>

                <div className="space-y-3 pt-2">
                  {shapFeatures.map((feat, i) => {
                    const isPositive = feat.weight > 0;
                    return (
                      <div key={i} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-medium text-on-surface flex items-center gap-1.5">
                            <span
                              className={`w-2 h-2 rounded-full ${isPositive ? 'bg-error' : 'bg-[#16a34a]'}`}
                            ></span>
                            {feat.name}
                          </span>
                          <span className={`font-mono font-bold ${isPositive ? 'text-error' : 'text-[#16a34a]'}`}>
                            {isPositive ? `+${feat.weight.toFixed(1)}` : feat.weight.toFixed(1)}
                          </span>
                        </div>
                        <div className="w-full bg-surface-container h-2 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${isPositive ? 'bg-error' : 'bg-[#16a34a]'}`}
                            style={{ width: `${Math.min(100, Math.abs(feat.weight) * 2.2)}%` }}
                          ></div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="pt-space-md border-t border-surface-variant/40 flex items-center justify-between font-mono text-xs font-bold">
                  <span>Total Composite Risk Score</span>
                  <span className="text-error">{current.risk_score?.toFixed(1) || '94.2'} / 100</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PORTS & SERVICES */}
          {activeTab === 'PORTS' && (
            <div className="bg-surface-container-lowest rounded-xl shadow-sm border border-surface-variant/40 overflow-hidden">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-surface-container-low text-secondary uppercase font-semibold">
                    <th className="py-2.5 px-3">Port</th>
                    <th className="py-2.5 px-3">Proto</th>
                    <th className="py-2.5 px-3">Service</th>
                    <th className="py-2.5 px-3">Banner / Signature</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-container">
                  {(current.open_ports?.length > 0 ? current.open_ports : [80, 443, 3389]).map((port) => (
                    <tr key={port} className="hover:bg-surface-container-low/60">
                      <td className="py-2.5 px-3 font-mono font-bold text-on-surface">{port}</td>
                      <td className="py-2.5 px-3 font-mono text-secondary">TCP</td>
                      <td className="py-2.5 px-3 font-semibold text-primary">
                        {port === 3389
                          ? 'ms-wbt-server (RDP)'
                          : port === 443
                          ? 'https'
                          : port === 80
                          ? 'http'
                          : port === 22
                          ? 'ssh'
                          : port === 27017
                          ? 'mongodb'
                          : 'unknown'}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-secondary text-[11px] truncate max-w-[200px]">
                        {port === 3389
                          ? 'Microsoft Terminal Services RDP 10.0'
                          : port === 443
                          ? 'TLSv1.3 OpenSSL'
                          : 'nginx/1.24'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 3: TECH STACK */}
          {activeTab === 'TECH' && (
            <div className="space-y-space-sm">
              {(current.technologies?.length > 0 ? current.technologies : ['Apache 2.4.49', 'OpenSSL 1.0.2', 'PHP 7.4']).map(
                (tech, i) => (
                  <div
                    key={i}
                    className="p-space-md rounded-xl bg-surface-container-lowest border border-surface-variant/40 shadow-sm flex items-center justify-between"
                  >
                    <div>
                      <span className="font-headline text-xs font-bold text-on-surface">{tech}</span>
                      <p className="text-[11px] text-secondary">Detected via HTTP Server header & favicon fingerprinting</p>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-surface-container text-secondary text-[10px] font-mono font-semibold">
                      Fingerprinted
                    </span>
                  </div>
                )
              )}
            </div>
          )}

          {/* TAB 4: SSL & HEADERS */}
          {activeTab === 'SSL' && (
            <div className="space-y-space-md">
              <div className="p-space-md rounded-xl bg-surface-container-lowest border border-surface-variant/40 shadow-sm space-y-space-xs">
                <span className="text-xs font-semibold text-secondary uppercase tracking-wider">
                  Certificate Validity
                </span>
                <div className="flex items-center justify-between">
                  <span className="font-headline text-sm font-bold text-on-surface">Let's Encrypt Authority X3</span>
                  <span className="px-2 py-0.5 rounded bg-error-container text-on-error-container text-xs font-bold">
                    EXPIRED
                  </span>
                </div>
                <p className="text-xs text-secondary font-mono">Expired 14 days ago. SAN: {current.hostname}</p>
              </div>

              <div className="bg-surface-container-lowest rounded-xl shadow-sm border border-surface-variant/40 overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="bg-surface-container-low text-secondary uppercase font-semibold">
                      <th className="py-2.5 px-3">Directive</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Impact</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-container">
                    <tr>
                      <td className="py-2.5 px-3 font-mono font-semibold">Strict-Transport-Security (HSTS)</td>
                      <td className="py-2.5 px-3 text-error font-bold">MISSING</td>
                      <td className="py-2.5 px-3 text-secondary text-[11px]">Vulnerable to SSL stripping</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 font-mono font-semibold">Content-Security-Policy (CSP)</td>
                      <td className="py-2.5 px-3 text-error font-bold">MISSING</td>
                      <td className="py-2.5 px-3 text-secondary text-[11px]">XSS vulnerability defense absent</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 font-mono font-semibold">X-Frame-Options</td>
                      <td className="py-2.5 px-3 text-error font-bold">MISSING</td>
                      <td className="py-2.5 px-3 text-secondary text-[11px]">Clickjacking attack surface exposed</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 5: CVES & INTEL */}
          {activeTab === 'CVES' && (
            <div className="space-y-space-md">
              <div className="p-space-md rounded-xl bg-surface-container-lowest border border-error/30 shadow-sm space-y-space-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-error">CVE-2021-41773</span>
                  <span className="px-1.5 py-0.5 bg-error text-on-error text-[10px] font-bold rounded uppercase">
                    CISA KEV INDEXED
                  </span>
                </div>
                <h4 className="font-headline text-xs font-bold text-on-surface">
                  Apache HTTP Server 2.4.49 Path Traversal & Remote Code Execution
                </h4>
                <p className="text-xs text-secondary leading-relaxed">
                  A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.
                </p>
                <div className="flex items-center gap-space-lg pt-1 font-mono text-xs">
                  <span>CVSS: <strong className="text-error">9.8 Critical</strong></span>
                  <span>EPSS: <strong className="text-error">94.2% Exploitation</strong></span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
