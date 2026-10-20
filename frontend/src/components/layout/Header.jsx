import React from 'react';

export default function Header({
  activeTarget = 'example.com',
  onTargetChange,
  onOpenNewScan,
  activeAssetsCount = 0,
  searchTerm = '',
  onSearchChange,
}) {
  return (
    <header className="fixed top-0 left-0 right-0 h-14 bg-surface-container-lowest z-50 shadow-[0_1px_3px_0_rgba(0,0,0,0.05)] flex items-center justify-between px-margin border-b border-surface-variant">
      {/* Brand & Target */}
      <div className="flex items-center gap-space-lg">
        <div className="flex items-center gap-space-xs cursor-pointer select-none">
          <div className="w-8 h-8 rounded-lg bg-primary-container text-on-primary flex items-center justify-center font-bold shadow-sm">
            <span className="material-symbols-outlined text-[20px]">shield</span>
          </div>
          <span className="font-headline text-lg text-on-surface tracking-tight uppercase font-bold ml-space-xxs">
            AEGIS
          </span>
          <span className="font-body text-[11px] px-space-xs py-0.5 bg-secondary-container text-on-secondary-fixed font-semibold uppercase tracking-wider rounded">
            Enterprise
          </span>
        </div>

        <div className="h-5 w-[1px] bg-outline-variant hidden sm:block"></div>

        {/* Target Indicator */}
        <div className="hidden md:flex items-center gap-space-xs px-space-sm py-1 rounded bg-surface-container-low hover:bg-surface-container transition-colors">
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
          </span>
          <span className="text-xs text-on-surface-variant font-medium">Target:</span>
          <span className="font-mono text-xs text-on-surface font-semibold">{activeTarget}</span>
        </div>
      </div>

      {/* Global Search Bar */}
      <div className="flex-1 max-w-md mx-margin hidden lg:block">
        <div className="relative flex items-center w-full">
          <span className="material-symbols-outlined absolute left-space-sm text-outline text-[18px]">
            search
          </span>
          <input
            type="text"
            className="w-full h-8 pl-8 pr-16 bg-surface-container-lowest border border-outline-variant rounded text-xs text-on-surface placeholder-on-surface-variant/70 focus:outline-none focus:border-primary-container focus:ring-1 focus:ring-primary-container"
            placeholder="Search subdomains, IPs, CVEs..."
            value={searchTerm}
            onChange={(e) => onSearchChange && onSearchChange(e.target.value)}
          />
          <div className="absolute right-space-xs flex items-center">
            <kbd className="font-mono text-[10px] px-1.5 py-0.5 bg-surface-container text-on-surface-variant border border-outline-variant/60 rounded">
              ⌘K
            </kbd>
          </div>
        </div>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-space-md">
        <div className="hidden xl:flex items-center gap-space-xs px-space-sm py-1 rounded bg-surface-container-low">
          <span className="material-symbols-outlined text-primary-container text-[16px]">dns</span>
          <span className="font-mono text-xs text-on-surface font-semibold">{activeAssetsCount || 184}</span>
          <span className="text-xs text-on-surface-variant">Assets Active</span>
        </div>

        <button
          onClick={onOpenNewScan}
          className="inline-flex items-center gap-space-xs h-8 px-space-md bg-primary-container hover:bg-primary text-on-primary text-xs font-semibold rounded transition-colors shadow-sm cursor-pointer"
          type="button"
        >
          <span className="material-symbols-outlined text-[16px]">add</span>
          <span>Start Scan</span>
        </button>
      </div>
    </header>
  );
}
