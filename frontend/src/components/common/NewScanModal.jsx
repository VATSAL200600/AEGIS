import React, { useState, useEffect } from 'react';
import { createScan } from '../../services/api';

export default function NewScanModal({ isOpen, onClose, onScanCreated }) {
  const [domain, setDomain] = useState('example.com');
  const [profile, setProfile] = useState('standard');
  const [enableIntel, setEnableIntel] = useState(true);
  const [enablePorts, setEnablePorts] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    // Basic domain validation
    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!cleanDomain || !cleanDomain.includes('.')) {
      setError('Please enter a valid root domain (e.g., example.com)');
      return;
    }

    setLoading(true);
    try {
      const res = await createScan({
        target_domain: cleanDomain,
        scan_profile: profile,
        enable_threat_intel: enableIntel,
        enable_port_scan: enablePorts,
      });
      setLoading(false);
      onClose();
      if (onScanCreated) {
        onScanCreated(res);
      }
    } catch (err) {
      setLoading(false);
      setError(err.message || 'Failed to start scan');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-xl bg-surface-container-lowest rounded-xl shadow-xl border border-surface-variant overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-space-lg border-b border-surface-variant bg-surface-container-lowest">
          <div className="flex items-center gap-space-xs">
            <div className="p-1.5 rounded-lg bg-primary-container text-on-primary">
              <span className="material-symbols-outlined text-[18px]">radar</span>
            </div>
            <div>
              <h2 className="font-headline text-base font-bold text-on-surface">Launch Attack Surface Scan</h2>
              <p className="text-xs text-secondary">Initiate continuous reconnaissance and vulnerability discovery</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-outline hover:text-on-surface hover:bg-surface-container transition-colors"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-space-lg space-y-space-lg">
          {error && (
            <div className="p-space-sm rounded bg-error-container text-on-error-container text-xs flex items-center gap-space-xs">
              <span className="material-symbols-outlined text-[16px] text-error">error</span>
              <span>{error}</span>
            </div>
          )}

          {/* Domain Input */}
          <div>
            <label className="block text-xs font-semibold text-on-surface-variant mb-space-xs">
              Primary Target Root Domain
            </label>
            <div className="relative flex items-center">
              <span className="material-symbols-outlined absolute left-space-md text-outline text-[18px]">dns</span>
              <input
                type="text"
                className="w-full h-10 pl-10 pr-4 bg-surface-container-low rounded-lg font-mono text-xs text-on-surface focus:outline-none focus:bg-surface-container-lowest focus:ring-2 focus:ring-primary-container transition-all"
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required
              />
            </div>
            <p className="text-[11px] text-secondary mt-1">
              Do not include protocol (https://) or paths. Scope to authorized apex domains.
            </p>
          </div>

          {/* Profile Bento */}
          <div>
            <label className="block text-xs font-semibold text-on-surface-variant mb-space-xs">
              Select Operational Profile
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-space-sm">
              {/* Quick */}
              <div
                onClick={() => setProfile('quick')}
                className={`p-space-md rounded-xl cursor-pointer border transition-all ${
                  profile === 'quick'
                    ? 'border-primary-container bg-secondary-container/30 ring-1 ring-primary-container shadow-sm'
                    : 'border-surface-variant bg-surface-container-low hover:bg-surface-container'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-xs text-on-surface flex items-center gap-1">
                    <span className="material-symbols-outlined text-[16px] text-secondary">bolt</span>
                    Quick
                  </span>
                  <span className="font-mono text-[10px] text-secondary">~1 min</span>
                </div>
                <p className="text-[11px] text-secondary leading-snug">CT logs & top 20 ports.</p>
              </div>

              {/* Standard */}
              <div
                onClick={() => setProfile('standard')}
                className={`p-space-md rounded-xl cursor-pointer border transition-all relative ${
                  profile === 'standard'
                    ? 'border-primary-container bg-secondary-container/40 ring-1 ring-primary-container shadow-sm'
                    : 'border-surface-variant bg-surface-container-low hover:bg-surface-container'
                }`}
              >
                <div className="absolute -top-2 right-2 px-1 py-0.2 bg-primary-container text-on-primary text-[9px] font-bold rounded uppercase tracking-wider">
                  REC
                </div>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-xs text-primary flex items-center gap-1">
                    <span className="material-symbols-outlined text-[16px] text-primary-container">verified</span>
                    Standard
                  </span>
                  <span className="font-mono text-[10px] text-primary font-semibold">~3 min</span>
                </div>
                <p className="text-[11px] text-on-surface leading-snug">Subdomains + Top 100 ports + SSL + CVEs.</p>
              </div>

              {/* Deep */}
              <div
                onClick={() => setProfile('deep')}
                className={`p-space-md rounded-xl cursor-pointer border transition-all ${
                  profile === 'deep'
                    ? 'border-primary-container bg-secondary-container/30 ring-1 ring-primary-container shadow-sm'
                    : 'border-surface-variant bg-surface-container-low hover:bg-surface-container'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-xs text-on-surface flex items-center gap-1">
                    <span className="material-symbols-outlined text-[16px] text-secondary">troubleshoot</span>
                    Deep
                  </span>
                  <span className="font-mono text-[10px] text-secondary">~6 min</span>
                </div>
                <p className="text-[11px] text-secondary leading-snug">Full brute force + banners + takeover heuristics.</p>
              </div>
            </div>
          </div>

          {/* Options */}
          <div className="flex items-center gap-space-lg pt-space-xs">
            <label className="flex items-center gap-space-xs cursor-pointer select-none text-xs text-on-surface">
              <input
                type="checkbox"
                className="w-4 h-4 rounded accent-primary-container"
                checked={enablePorts}
                onChange={(e) => setEnablePorts(e.target.checked)}
              />
              <span>Port Discovery</span>
            </label>
            <label className="flex items-center gap-space-xs cursor-pointer select-none text-xs text-on-surface">
              <input
                type="checkbox"
                className="w-4 h-4 rounded accent-primary-container"
                checked={enableIntel}
                onChange={(e) => setEnableIntel(e.target.checked)}
              />
              <span>Threat Intel Enrichment</span>
            </label>
          </div>

          {/* Footer buttons */}
          <div className="flex items-center justify-end gap-space-sm pt-space-md border-t border-surface-variant">
            <button
              type="button"
              onClick={onClose}
              className="h-9 px-space-md bg-surface-container-low hover:bg-surface-container text-on-surface text-xs font-medium rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center justify-center gap-space-xs h-9 px-space-xl bg-primary-container hover:bg-primary text-on-primary text-xs font-semibold rounded-lg shadow-sm transition-all disabled:opacity-50"
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined text-[16px] animate-spin">progress_activity</span>
                  <span>Launching...</span>
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-[16px]">play_circle</span>
                  <span>Launch Scan</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
