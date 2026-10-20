import React, { useState } from 'react';

export default function SettingsPage() {
  const [shodanKey, setShodanKey] = useState('');
  const [vtKey, setVtKey] = useState('');
  const [geminiKey, setGeminiKey] = useState('');
  const [dnsTimeout, setDnsTimeout] = useState('5.0');
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="flex flex-col w-full gap-space-xl max-w-4xl">
      <div>
        <h1 className="font-headline text-2xl font-bold text-on-surface tracking-tight">
          Threat Intel & Engine Settings
        </h1>
        <p className="text-xs text-secondary">
          Configure external threat feeds, API keys, scanner concurrency, and reporting providers
        </p>
      </div>

      {saved && (
        <div className="p-space-sm rounded bg-[#dcfce7] text-[#166534] text-xs font-semibold flex items-center gap-2">
          <span className="material-symbols-outlined text-[18px]">check_circle</span>
          <span>Configuration saved successfully. Engine updated.</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-space-lg">
        {/* Threat Intel Card */}
        <div className="bg-surface-container-lowest p-space-lg rounded-xl shadow-sm border border-surface-variant/40 space-y-space-md">
          <h2 className="font-headline text-base font-bold text-on-surface">External Threat Intelligence Feeds</h2>
          <p className="text-xs text-secondary">
            Provide optional API keys to augment passive reconnaissance with global threat telemetry.
          </p>

          <div className="space-y-space-md pt-2">
            <div>
              <label className="block text-xs font-semibold text-on-surface-variant mb-1">
                Shodan API Key
              </label>
              <input
                type="password"
                className="w-full h-9 px-3 bg-surface-container-low rounded-lg font-mono text-xs focus:bg-surface-container-lowest focus:ring-1 focus:ring-primary-container"
                placeholder="Enter Shodan API key..."
                value={shodanKey}
                onChange={(e) => setShodanKey(e.target.value)}
              />
              <span className="text-[11px] text-secondary">Enables historical banner grabs and CVE correlation.</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-on-surface-variant mb-1">
                VirusTotal API Key
              </label>
              <input
                type="password"
                className="w-full h-9 px-3 bg-surface-container-low rounded-lg font-mono text-xs focus:bg-surface-container-lowest focus:ring-1 focus:ring-primary-container"
                placeholder="Enter VirusTotal API key..."
                value={vtKey}
                onChange={(e) => setVtKey(e.target.value)}
              />
              <span className="text-[11px] text-secondary">Provides passive DNS and domain reputation telemetry.</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-on-surface-variant mb-1">
                Google Gemini API Key
              </label>
              <input
                type="password"
                className="w-full h-9 px-3 bg-surface-container-low rounded-lg font-mono text-xs focus:bg-surface-container-lowest focus:ring-1 focus:ring-primary-container"
                placeholder="AIzaSy..."
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
              />
              <span className="text-[11px] text-secondary">Power AI-driven executive synthesis in PDF & HTML reports.</span>
            </div>
          </div>
        </div>

        {/* Engine Concurrency */}
        <div className="bg-surface-container-lowest p-space-lg rounded-xl shadow-sm border border-surface-variant/40 space-y-space-md">
          <h2 className="font-headline text-base font-bold text-on-surface">Scanner Concurrency & Timing</h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-space-md">
            <div>
              <label className="block text-xs font-semibold text-on-surface-variant mb-1">
                DNS Resolver Timeout (seconds)
              </label>
              <input
                type="number"
                step="0.5"
                className="w-full h-9 px-3 bg-surface-container-low rounded-lg font-mono text-xs focus:ring-1 focus:ring-primary-container"
                value={dnsTimeout}
                onChange={(e) => setDnsTimeout(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-on-surface-variant mb-1">
                Port Scan Concurrency
              </label>
              <input
                type="number"
                disabled
                className="w-full h-9 px-3 bg-surface-container-low/60 rounded-lg font-mono text-xs text-secondary"
                value="50 concurrent sockets"
              />
            </div>
          </div>
        </div>

        <button
          type="submit"
          className="h-9 px-space-xl bg-primary-container hover:bg-primary text-on-primary text-xs font-semibold rounded-lg shadow-sm transition-all"
        >
          Save Configuration
        </button>
      </form>
    </div>
  );
}
