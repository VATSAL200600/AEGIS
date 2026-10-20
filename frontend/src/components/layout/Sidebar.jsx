import React from 'react';

export default function Sidebar({ activeTab, onSelectTab }) {
  const navItem = (tabId, label, icon) => {
    const isActive = activeTab === tabId;
    return (
      <button
        type="button"
        onClick={() => onSelectTab(tabId)}
        className={`w-full flex items-center gap-space-sm px-space-sm py-space-xs rounded text-left transition-colors text-xs ${
          isActive
            ? 'bg-primary-container text-on-primary font-semibold shadow-sm'
            : 'text-on-surface-variant hover:bg-surface-container-low hover:text-on-surface font-medium'
        }`}
      >
        <span className={`material-symbols-outlined text-[20px] ${isActive ? 'text-on-primary' : 'text-outline'}`}>
          {icon}
        </span>
        <span>{label}</span>
      </button>
    );
  };

  return (
    <aside className="fixed left-0 top-14 bottom-0 w-60 bg-surface-container-lowest border-r border-surface-variant z-40 flex flex-col justify-between overflow-y-auto">
      <div className="px-space-md py-space-lg">
        {/* Monitoring Group */}
        <div className="mb-space-xl">
          <span className="block text-[11px] font-semibold text-outline uppercase tracking-wider px-space-sm mb-space-xs">
            Monitoring
          </span>
          <nav className="space-y-space-xxs">
            {navItem('overview', 'Overview', 'grid_view')}
            {navItem('assets', 'Asset Inventory', 'dns')}
          </nav>
        </div>

        {/* Operations Group */}
        <div className="mb-space-xl">
          <span className="block text-[11px] font-semibold text-outline uppercase tracking-wider px-space-sm mb-space-xs">
            Operations
          </span>
          <nav className="space-y-space-xxs">
            {navItem('scans', 'Scan Center', 'radar')}
            {navItem('reports', 'Executive Reports', 'assessment')}
          </nav>
        </div>

        {/* Configuration Group */}
        <div>
          <span className="block text-[11px] font-semibold text-outline uppercase tracking-wider px-space-sm mb-space-xs">
            Configuration
          </span>
          <nav className="space-y-space-xxs">
            {navItem('settings', 'Threat Intel & Settings', 'tune')}
          </nav>
        </div>
      </div>

      {/* Footer System Status */}
      <div className="p-space-md border-t border-surface-variant bg-surface-container-lowest">
        <div className="flex items-center justify-between px-space-sm py-space-xs rounded bg-surface-container-low">
          <div className="flex items-center gap-space-xs">
            <span className="inline-block w-2 h-2 rounded-full bg-primary"></span>
            <span className="text-[11px] text-on-surface-variant font-medium">Recon Engine</span>
          </div>
          <span className="font-mono text-[11px] text-on-surface font-semibold">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
}
