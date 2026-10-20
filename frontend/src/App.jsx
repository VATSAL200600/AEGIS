import React, { useState } from 'react';
import Header from './components/layout/Header';
import Sidebar from './components/layout/Sidebar';
import OverviewPage from './components/dashboard/OverviewPage';
import ScanCenterPage from './components/scans/ScanCenterPage';
import AssetInventoryPage from './components/assets/AssetInventoryPage';
import AssetDetailDrawer from './components/assets/AssetDetailDrawer';
import ReportsPage from './components/reports/ReportsPage';
import SettingsPage from './components/settings/SettingsPage';
import NewScanModal from './components/common/NewScanModal';

function pathToTab(pathname) {
  const p = (pathname || '').toLowerCase();
  if (p.includes('/scans')) return 'scans';
  if (p.includes('/assets')) return 'assets';
  if (p.includes('/reports')) return 'reports';
  if (p.includes('/settings')) return 'settings';
  return 'overview';
}

function tabToPath(tab) {
  switch (tab) {
    case 'scans': return '/scans';
    case 'assets': return '/assets';
    case 'reports': return '/reports';
    case 'settings': return '/settings';
    default: return '/';
  }
}

export default function App() {
  const [activeTab, setActiveTabState] = useState(() => {
    if (typeof window !== 'undefined') {
      return pathToTab(window.location.pathname);
    }
    return 'overview';
  });

  const setActiveTab = (tab) => {
    setActiveTabState(tab);
    if (typeof window !== 'undefined') {
      const newPath = tabToPath(tab);
      if (window.location.pathname !== newPath) {
        window.history.pushState({ tab }, '', newPath);
      }
    }
  };

  React.useEffect(() => {
    const handlePopState = () => {
      setActiveTabState(pathToTab(window.location.pathname));
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const [activeTarget, setActiveTarget] = useState('example.com');
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const handleSelectAsset = (asset) => {
    setSelectedAsset(asset);
    setIsDrawerOpen(true);
  };

  const handleScanCreated = (scan) => {
    if (scan?.target_domain) {
      setActiveTarget(scan.target_domain);
    }
    setActiveTab('scans');
  };

  return (
    <div className="min-h-screen bg-surface font-body text-on-surface antialiased flex flex-col">
      {/* Top Navigation */}
      <Header
        activeTarget={activeTarget}
        onTargetChange={setActiveTarget}
        onOpenNewScan={() => setIsNewScanOpen(true)}
        activeAssetsCount={184}
        searchTerm={searchTerm}
        onSearchChange={(q) => {
          setSearchTerm(q);
          if (activeTab !== 'assets' && q.trim()) {
            setActiveTab('assets');
          }
        }}
      />

      {/* Main Structural Body */}
      <div className="flex flex-1 pt-14">
        {/* Sidebar */}
        <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />

        {/* Viewport Canvas (Left offset for 60px/240px sidebar) */}
        <main className="flex-1 ml-60 min-h-[calc(100vh-3.5rem)] px-margin py-space-xl overflow-x-hidden">
          {activeTab === 'overview' && (
            <OverviewPage
              activeTarget={activeTarget}
              onOpenNewScan={() => setIsNewScanOpen(true)}
              onSelectAsset={handleSelectAsset}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'scans' && (
            <ScanCenterPage
              activeTarget={activeTarget}
              onScanStarted={handleScanCreated}
            />
          )}

          {activeTab === 'assets' && (
            <AssetInventoryPage
              activeTarget={activeTarget}
              onSelectAsset={handleSelectAsset}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsPage activeTarget={activeTarget} />
          )}

          {activeTab === 'settings' && (
            <SettingsPage />
          )}
        </main>
      </div>

      {/* Slide-over Asset Detail Drawer */}
      <AssetDetailDrawer
        asset={selectedAsset}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        onRescan={(asset) => {
          setIsDrawerOpen(false);
          setActiveTab('scans');
        }}
      />

      {/* New Scan Launcher Modal */}
      <NewScanModal
        isOpen={isNewScanOpen}
        onClose={() => setIsNewScanOpen(false)}
        onScanCreated={handleScanCreated}
      />
    </div>
  );
}
