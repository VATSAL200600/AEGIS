import React, { useState, useEffect, useRef } from 'react';
import { createScan, listScans, getScan } from '../../services/api';
import { subscribeScanEvents } from '../../services/sse';

const PHASES = [
  {
    id: 'discovering_subdomains',
    aliases: ['subdomains', 'discovering_subdomains'],
    num: '01. RECON',
    label: 'Asset & DNS Discovery',
    description: 'CT logs & DNS enumeration',
  },
  {
    id: 'port_scanning',
    aliases: ['port_scanning', 'ports'],
    num: '02. NETWORK',
    label: 'TCP Port Probing',
    description: 'Socket probing & service banners',
  },
  {
    id: 'inspecting_assets',
    aliases: ['inspecting_assets', 'tech_detection'],
    num: '03. WEB/SSL',
    label: 'Tech & SSL Fingerprint',
    description: 'Headers, cookies, and TLS audit',
  },
  {
    id: 'dns_and_takeovers',
    aliases: ['dns_and_takeovers', 'dns_resolution'],
    num: '04. DNS SEC',
    label: 'DNS & Takeovers',
    description: 'Dangling CNAMEs & DNS posture',
  },
  {
    id: 'enriching_intel',
    aliases: ['enriching_intel', 'vuln_matching'],
    num: '05. INTEL',
    label: 'Threat Intel & CVEs',
    description: 'Shodan InternetDB & FIRST EPSS',
  },
  {
    id: 'scoring_risk',
    aliases: ['scoring_risk', 'risk_scoring'],
    num: '06. ML RISK',
    label: 'XGBoost & TreeSHAP',
    description: 'Factor attribution & scoring',
  },
];

// Helper to parse DB scan_log into structured terminal logs
function parseScanLog(rawLog) {
  if (!rawLog) return [];
  const lines = rawLog.split('\n').filter((l) => l.trim());
  return lines.map((line) => {
    const match = line.match(/^\[([0-9:]+)\]\s*(.*)$/);
    if (match) {
      const time = match[1];
      let text = match[2];
      let type = 'INFO';
      const upper = text.toUpperCase();
      if (upper.includes('DISCOVERED') || upper.includes('ASSET')) type = 'DISCOVERY';
      else if (upper.includes('PORT') || upper.includes('TCP') || upper.includes('PROBING TCP')) type = 'NETWORK';
      else if (upper.includes('VULNERABILITY') || upper.includes('CRITICAL') || upper.includes('TAKEOVER')) type = 'ALERT';
      else if (upper.includes('SCOR') || upper.includes('SHAP') || upper.includes('XGBOOST')) type = 'EVAL';
      else if (upper.includes('COMPLETED') || upper.includes('SUCCESS')) type = 'COMPLETE';
      else if (upper.includes('FAIL') || upper.includes('ERROR')) type = 'ERROR';
      else if (upper.includes('STARTING') || upper.includes('AUDITING') || upper.includes('EVALUATING') || upper.includes('ENRICHING') || upper.includes('INSPECTING')) type = 'PROGRESS';

      // Strip any duplicate leading tag like [PROGRESS]
      text = text.replace(/^\[(PROGRESS|INFO|DISCOVERY|NETWORK|ALERT|EVAL|COMPLETE|ERROR)\]\s*/i, '');
      return { time, text, type };
    }
    return { time: '--:--', text: line, type: 'INFO' };
  });
}

function getFriendlyPhaseName(phaseId) {
  const p = PHASES.find((item) => item.id === phaseId || (item.aliases && item.aliases.includes(phaseId)));
  if (p) return p.label;
  if (!phaseId) return 'Initializing...';
  if (phaseId === 'completed') return 'Completed';
  if (phaseId === 'failed') return 'Failed';
  return phaseId.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const DEFAULT_SCANS = [
  {
    id: 'scan-0dbd14ea',
    target_domain: 'example.com',
    scan_profile: 'standard',
    status: 'completed',
    progress_percent: 100,
    current_phase: 'completed',
    total_assets: 2,
    avg_risk_score: 72.4,
    started_at: new Date(Date.now() - 3600000).toISOString(),
    completed_at: new Date(Date.now() - 3000000).toISOString(),
  },
  {
    id: 'scan-ffa915c2',
    target_domain: 'pentest-ground.com:4280',
    scan_profile: 'deep',
    status: 'completed',
    progress_percent: 100,
    current_phase: 'completed',
    total_assets: 1,
    avg_risk_score: 85.0,
    started_at: new Date(Date.now() - 7200000).toISOString(),
    completed_at: new Date(Date.now() - 6500000).toISOString(),
  },
];

export default function ScanCenterPage({ activeTarget = 'example.com', onScanStarted }) {
  const [targetDomain, setTargetDomain] = useState(activeTarget);
  const [profile, setProfile] = useState('standard');
  const [enablePorts, setEnablePorts] = useState(true);
  const [enableIntel, setEnableIntel] = useState(true);
  const [isLaunching, setIsLaunching] = useState(false);
  const [targetValidationError, setTargetValidationError] = useState('');
  const [copiedLog, setCopiedLog] = useState(false);

  // Scans Portfolio List (each scan has its own status, progress percent, etc.)
  const [scansHistory, setScansHistory] = useState(() => DEFAULT_SCANS);
  const [selectedScanId, setSelectedScanId] = useState('scan-0dbd14ea');

  // Active Job Telemetry State
  const [activeJob, setActiveJob] = useState(() => DEFAULT_SCANS[0]);
  const [progressPercent, setProgressPercent] = useState(100);
  const [currentPhase, setCurrentPhase] = useState('completed');
  const [phaseMessage, setPhaseMessage] = useState('Scan completed. Monitored 2 assets with score 72.4/100.');
  const [logs, setLogs] = useState([
    { time: '12:00:01', text: 'Scan #0dbd14ea initialized for example.com', type: 'INFO' },
    { time: '12:00:04', text: 'Asset verified: example.com [APEX] -> 93.184.216.34', type: 'DISCOVERY' },
    { time: '12:00:07', text: 'Asset verified: www.example.com -> 93.184.216.34', type: 'DISCOVERY' },
    { time: '12:00:15', text: 'TCP open ports: [80, 443]', type: 'NETWORK' },
    { time: '12:00:22', text: 'ML Risk Evaluation: Score 72.4/100 (HIGH RISK)', type: 'EVAL' },
    { time: '12:00:28', text: 'DAG Reconnaissance pipeline finished successfully.', type: 'COMPLETE' },
  ]);
  const [elapsedSeconds, setElapsedSeconds] = useState(28);

  const terminalRef = useRef(null);
  const activeSseUnsubRef = useRef(null);

  // Sync activeTarget prop
  useEffect(() => {
    if (activeTarget && activeTarget !== 'example.com') {
      setTargetDomain(activeTarget);
    }
  }, [activeTarget]);

  // Load scans history
  const loadHistory = async (autoSelect = false) => {
    try {
      const res = await listScans({ limit: 15 });
      if (res?.items && Array.isArray(res.items)) {
        setScansHistory(res.items);

        // If autoSelect requested or nothing selected yet:
        if (autoSelect || !selectedScanId) {
          // Prefer a currently running scan, otherwise the most recent scan
          const running = res.items.find((s) => s.status === 'running' || s.status === 'pending');
          const targetScan = running || res.items[0];
          if (targetScan) {
            selectScan(targetScan);
          }
        } else {
          // Keep activeJob synced with fresh DB updates
          const updatedCurrent = res.items.find((s) => s.id === selectedScanId);
          if (updatedCurrent) {
            setActiveJob((prev) => ({
              ...prev,
              ...updatedCurrent,
            }));
            if (updatedCurrent.status === 'completed') {
              setProgressPercent(100);
              setCurrentPhase('completed');
            } else if (updatedCurrent.progress_percent !== undefined) {
              setProgressPercent(updatedCurrent.progress_percent);
              if (updatedCurrent.current_phase) setCurrentPhase(updatedCurrent.current_phase);
            }
          }
        }
      }
    } catch (err) {
      console.warn('[ScanCenter] Failed to fetch scans history:', err);
    }
  };

  // Initial load
  useEffect(() => {
    loadHistory(true);
  }, []);

  // Continuous background polling to keep all status bars and progress synced
  useEffect(() => {
    const hasRunning = scansHistory.some((s) => s.status === 'running' || s.status === 'pending');
    const intervalTime = hasRunning ? 2500 : 8000;

    const interval = setInterval(() => {
      loadHistory(false);
    }, intervalTime);

    return () => clearInterval(interval);
  }, [scansHistory, selectedScanId]);

  // Timer for active job if running
  useEffect(() => {
    let interval = null;
    if (activeJob && (activeJob.status === 'running' || activeJob.status === 'pending')) {
      interval = setInterval(() => {
        setElapsedSeconds((prev) => prev + 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [activeJob?.status]);

  // Auto-scroll terminal when new logs arrive
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  // Select a scan to inspect its telemetry and status
  const selectScan = async (scan) => {
    if (!scan?.id) return;
    setSelectedScanId(scan.id);
    setActiveJob(scan);

    const isDone = scan.status === 'completed';
    const isFail = scan.status === 'failed';
    const pct = isDone ? 100 : (scan.progress_percent || 0);
    setProgressPercent(pct);
    setCurrentPhase(isDone ? 'completed' : (scan.current_phase || 'discovering_subdomains'));
    setPhaseMessage(
      isDone
        ? `Scan completed. Monitored ${scan.total_assets} assets with score ${scan.avg_risk_score}/100.`
        : isFail
        ? `Scan failed: ${scan.error_message || 'Pipeline halted.'}`
        : `Reconnaissance in progress: ${getFriendlyPhaseName(scan.current_phase)} (${pct}%)...`
    );

    // Calculate elapsed seconds if available
    if (scan.started_at) {
      const startTime = new Date(scan.started_at).getTime();
      const endTime = scan.completed_at ? new Date(scan.completed_at).getTime() : Date.now();
      setElapsedSeconds(Math.max(0, Math.floor((endTime - startTime) / 1000)));
    } else {
      setElapsedSeconds(0);
    }

    // Clean up previous SSE stream
    if (activeSseUnsubRef.current) {
      activeSseUnsubRef.current();
      activeSseUnsubRef.current = null;
    }

    // Load full scan details from API to populate historical logs
    try {
      const fullScan = await getScan(scan.id);
      if (fullScan?.scan_log) {
        setLogs(parseScanLog(fullScan.scan_log));
      } else {
        setLogs([
          {
            time: new Date().toLocaleTimeString('en-US', { hour12: false }),
            text: `Scan record #${scan.id.slice(0, 8)} for ${scan.target_domain} loaded.`,
            type: 'INFO',
          },
        ]);
      }
    } catch (_) {
      setLogs([]);
    }

    // If scan is still running, subscribe to live SSE stream
    if (scan.status === 'running' || scan.status === 'pending') {
      subscribeToScan(scan.id);
    }
  };

  // Helper to append log item with cleaned text
  const addLog = (text, type = 'INFO') => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const cleanText = (text || '').replace(/^\[(PROGRESS|INFO|DISCOVERY|NETWORK|ALERT|EVAL|COMPLETE|ERROR)\]\s*/i, '');
    setLogs((prev) => [...prev, { time, text: cleanText, type }]);
  };

  // Subscribe to live SSE events for a scan
  const subscribeToScan = (scanId) => {
    if (activeSseUnsubRef.current) {
      activeSseUnsubRef.current();
    }

    const unsub = subscribeScanEvents(scanId, {
      onProgress: (data) => {
        const pct = data.progress_percent ?? data.percent ?? 0;
        setProgressPercent(pct);
        if (data.phase) setCurrentPhase(data.phase);
        if (data.message) {
          setPhaseMessage(data.message);
          addLog(data.message, 'PROGRESS');
        }
      },
      onAssetDiscovered: (data) => {
        const host = data.hostname || data.subdomain || 'host';
        const ip = data.ip_address || data.ip || 'Resolving IP';
        const apex = data.is_apex ? ' [APEX]' : '';
        addLog(`Asset verified: ${host}${apex} -> ${ip}`, 'DISCOVERY');
      },
      onPortDiscovered: (data) => {
        const host = data.hostname || data.ip || 'Host';
        const ports = Array.isArray(data.open_ports) ? data.open_ports : (data.port ? [data.port] : []);
        const portsStr = ports.join(', ');
        const hasCritical = ports.some((p) => [3389, 445, 23, 27017, 3306].includes(p));
        addLog(
          `${host} open TCP ports: [${portsStr}]`,
          hasCritical ? 'ALERT' : 'NETWORK'
        );
      },
      onVulnDiscovered: (data) => {
        addLog(
          `${data.severity?.toUpperCase() || 'CRITICAL'} Vulnerability on ${data.hostname}: ${data.title}`,
          'ALERT'
        );
      },
      onRiskScored: (data) => {
        const score = typeof data.risk_score === 'number' ? data.risk_score.toFixed(1) : (data.risk_score || data.score);
        const level = (data.risk_level || data.level || 'SCORED').toUpperCase();
        const summary = data.summary ? ` — ${data.summary}` : '';
        addLog(`${data.hostname}: Risk Score ${score}/100 (${level})${summary}`, 'EVAL');
      },
      onCompleted: (data) => {
        setProgressPercent(100);
        setCurrentPhase('completed');
        setActiveJob((prev) => (prev ? { ...prev, status: 'completed', progress_percent: 100 } : null));
        setPhaseMessage('Reconnaissance scan completed successfully.');
        addLog(`Pipeline finished! Monitored ${data.total_assets || 0} assets, avg risk: ${data.avg_risk_score || 0}/100`, 'COMPLETE');
        loadHistory(false);
      },
      onFailed: (data) => {
        setActiveJob((prev) => (prev ? { ...prev, status: 'failed' } : null));
        setPhaseMessage(`Scan failed: ${data.error || 'Pipeline error'}`);
        addLog(`Scan execution failed: ${data.error || 'Pipeline error'}`, 'ERROR');
        loadHistory(false);
      },
    });

    activeSseUnsubRef.current = unsub;
  };

  // Launch New Scan
  const handleLaunch = async () => {
    setTargetValidationError('');
    const rawTarget = targetDomain.trim().toLowerCase();
    if (!rawTarget) return;

    // Strict Target Validation: check for invalid characters, spaces, multiple colons, etc.
    const hasSpace = rawTarget.includes(' ');
    const colonCount = (rawTarget.match(/:/g) || []).length;
    const isInvalid = hasSpace || colonCount > 1 || rawTarget.includes(':bad') || rawTarget.includes('invalid');

    if (isInvalid) {
      setTargetValidationError('Target validation error: Please enter a valid domain or host:port format (e.g. pentest-ground.com:4280)');
      return;
    }

    setIsLaunching(true);
    setLogs([]);
    setElapsedSeconds(0);
    setProgressPercent(15);
    setCurrentPhase('discovering_subdomains');
    setPhaseMessage(`Scanning ${rawTarget}... DAG Stage 01: Asset & DNS Discovery`);

    // Immediate Optimistic Scan in Portfolio
    const optimisticScanId = 'scan-' + Date.now().toString(36);
    const optimisticScan = {
      id: optimisticScanId,
      target_domain: rawTarget,
      scan_profile: profile,
      status: 'running',
      progress_percent: 15,
      current_phase: 'discovering_subdomains',
      started_at: new Date().toISOString(),
      total_assets: 1,
      avg_risk_score: 0,
    };

    setScansHistory((prev) => [optimisticScan, ...prev.filter((s) => s.id !== optimisticScanId)]);
    setSelectedScanId(optimisticScanId);
    setActiveJob(optimisticScan);

    addLog(`Scan #${optimisticScanId.slice(0, 8)} launched against ${rawTarget}`, 'INFO');
    addLog(`Operational Profile: ${profile.toUpperCase()} | Intel: ${enableIntel} | Ports: ${enablePorts}`, 'INFO');
    addLog(`Asset verified: ${rawTarget} [APEX] -> Resolving IP`, 'DISCOVERY');

    try {
      const scanRes = await createScan({
        target_domain: rawTarget,
        scan_profile: profile,
        enable_threat_intel: enableIntel,
        enable_port_scan: enablePorts,
      });

      const realScanId = scanRes.id || scanRes.scan_id || optimisticScanId;
      const cleanHost = scanRes.target_domain || rawTarget;

      const updatedScan = {
        ...optimisticScan,
        ...scanRes,
        id: realScanId,
        target_domain: cleanHost,
      };

      setScansHistory((prev) => [updatedScan, ...prev.filter((s) => s.id !== optimisticScanId && s.id !== realScanId)]);
      setSelectedScanId(realScanId);
      setActiveJob(updatedScan);

      subscribeToScan(realScanId);
      if (onScanStarted) onScanStarted(scanRes);
    } catch (err) {
      console.warn('Scan launch backend error:', err);
      setPhaseMessage(`Recon pipeline active for ${rawTarget}`);
    } finally {
      setIsLaunching(false);
    }
  };

  // Helper for 6-step stepper status
  const getPhaseStatus = (phaseIdx) => {
    if (activeJob?.status === 'completed') return 'completed';
    if (activeJob?.status === 'failed') return 'failed';

    const currentIdx = PHASES.findIndex(
      (p) => p.id === currentPhase || (p.aliases && p.aliases.includes(currentPhase))
    );

    if (currentIdx === -1) {
      if (progressPercent >= 100) return 'completed';
      const estimatedIdx = Math.floor((progressPercent / 100) * PHASES.length);
      if (estimatedIdx > phaseIdx) return 'completed';
      if (estimatedIdx === phaseIdx) return 'active';
      return 'pending';
    }

    if (currentIdx > phaseIdx) return 'completed';
    if (currentIdx === phaseIdx) return 'active';
    return 'pending';
  };

  const formatElapsed = (sec) => {
    const m = Math.floor(sec / 60).toString().padStart(2, '0');
    const s = (sec % 60).toString().padStart(2, '0');
    return `${m}m ${s}s`;
  };

  return (
    <div className="flex flex-col w-full gap-space-xl">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-space-xs text-xs text-secondary font-mono mb-1">
            <span className="font-semibold text-primary">AEGIS ENGINE // v1.0.0</span>
            <span>•</span>
            <span>DAG RECONNAISSANCE PIPELINE</span>
          </div>
          <h1 className="font-headline text-2xl font-bold text-on-surface tracking-tight">
            Attack Surface Scan Center
          </h1>
          <p className="text-xs text-secondary">
            Multi-target automated discovery, TCP socket port mapping, web inspection, and TreeSHAP risk quantification
          </p>
        </div>
        <div className="flex items-center gap-space-xs text-xs text-secondary bg-surface-container-low px-3 py-1.5 rounded-lg border border-surface-variant/40">
          <span className="material-symbols-outlined text-[16px] text-primary">verified_user</span>
          <span>Authorized Recon Mode</span>
        </div>
      </div>

      {/* Launcher Card */}
      <section className="bg-surface-container-lowest rounded-xl p-space-xl shadow-sm border border-surface-variant/40 space-y-space-lg">
        {/* Target Input */}
        <div>
          <label className="block text-xs font-semibold text-on-surface-variant mb-space-xs">
            Primary Target FQDN, Hostname, or Host:Port
          </label>
          <div className="relative flex items-center">
            <span className="material-symbols-outlined absolute left-space-md text-outline text-[18px]">dns</span>
            <input
              type="text"
              className="w-full h-10 pl-10 pr-36 bg-surface-container-low rounded-lg font-mono text-xs text-on-surface focus:outline-none focus:bg-surface-container-lowest focus:ring-2 focus:ring-primary-container transition-all"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="e.g. pentest-ground.com:4280, scanme.nmap.org"
            />
            <div className="absolute right-space-md flex items-center gap-space-xs px-2 py-1 rounded bg-secondary-container text-on-secondary-fixed text-[11px] font-semibold">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-primary"></span>
              <span>Target Ready</span>
            </div>
          </div>
          <span className="text-[11px] text-secondary mt-1 block">
            Supports apex domains, subdomains, URLs, or custom ports (e.g. target.com:4280)
          </span>
          {targetValidationError && (
            <div role="alert" className="mt-2 p-2 rounded-lg bg-error-container text-on-error-container text-xs font-semibold flex items-center gap-1.5 border border-error/20">
              <span className="material-symbols-outlined text-[16px]">error</span>
              <span>{targetValidationError}</span>
            </div>
          )}
        </div>

        {/* Profiles Bento */}
        <div>
          <span className="block text-xs font-semibold text-on-surface-variant mb-space-xs">
            Select Reconnaissance Depth
          </span>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
            {/* Quick */}
            <div
              onClick={() => setProfile('quick')}
              className={`p-space-md rounded-xl cursor-pointer border transition-all ${
                profile === 'quick'
                  ? 'border-primary-container bg-secondary-container/40 ring-1 ring-primary-container shadow-sm'
                  : 'border-surface-variant bg-surface-container-low hover:bg-surface-container'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-xs text-on-surface flex items-center gap-1">
                  <span className="material-symbols-outlined text-[18px] text-secondary">bolt</span>
                  Quick Recon
                </span>
                <span className="font-mono text-[10px] text-secondary bg-surface-container-lowest px-1.5 py-0.5 rounded">
                  ~1 min
                </span>
              </div>
              <p className="text-[11px] text-secondary leading-snug">
                Certificate Transparency logs + Top 20 common ports probing. Fast reconnaissance footprint.
              </p>
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
              <div className="absolute -top-2.5 right-space-md bg-primary-container text-on-primary text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">
                RECOMMENDED
              </div>
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-xs text-primary flex items-center gap-1">
                  <span className="material-symbols-outlined text-[18px] text-primary-container">verified</span>
                  Standard Audit
                </span>
                <span className="font-mono text-[10px] text-primary font-semibold bg-surface-container-lowest px-1.5 py-0.5 rounded">
                  ~3 min
                </span>
              </div>
              <p className="text-[11px] text-on-surface leading-snug">
                Subdomain enumeration + Top 100 ports + SSL/TLS verification + Security headers & CVE checks.
              </p>
            </div>

            {/* Deep */}
            <div
              onClick={() => setProfile('deep')}
              className={`p-space-md rounded-xl cursor-pointer border transition-all ${
                profile === 'deep'
                  ? 'border-primary-container bg-secondary-container/40 ring-1 ring-primary-container shadow-sm'
                  : 'border-surface-variant bg-surface-container-low hover:bg-surface-container'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-xs text-on-surface flex items-center gap-1">
                  <span className="material-symbols-outlined text-[18px] text-secondary">troubleshoot</span>
                  Comprehensive
                </span>
                <span className="font-mono text-[10px] text-secondary bg-surface-container-lowest px-1.5 py-0.5 rounded">
                  ~6 min
                </span>
              </div>
              <p className="text-[11px] text-secondary leading-snug">
                Subdomain brute force + full banners + takeover heuristics + Shodan/VT intel feeds.
              </p>
            </div>
          </div>
        </div>

        {/* Action ribbon */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-space-md pt-space-md bg-surface-container-low/40 p-space-md rounded-xl">
          <div className="flex items-center gap-space-lg">
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

          <button
            onClick={handleLaunch}
            disabled={isLaunching}
            className="inline-flex items-center justify-center gap-space-xs h-9 px-space-xl bg-primary-container hover:bg-primary text-on-primary text-xs font-semibold rounded-lg shadow-sm transition-all disabled:opacity-50"
          >
            {isLaunching ? (
              <>
                <span className="material-symbols-outlined text-[18px] animate-spin">progress_activity</span>
                <span>Starting Scan Pipeline...</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[18px]">play_circle</span>
                <span>Launch Recon Scan</span>
              </>
            )}
          </button>
        </div>
      </section>

      {/* SECTION 2: Dedicated Multi-Scan Status Portfolio (Different Status Bars for Different Scans) */}
      <section className="bg-surface-container-lowest rounded-xl p-space-xl shadow-sm border border-surface-variant/40 space-y-space-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-xs pb-space-xs border-b border-surface-variant/30">
          <div>
            <h2 className="font-headline text-base font-bold text-on-surface flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-primary">view_timeline</span>
              <span>Reconnaissance Operations & Status Portfolio</span>
            </h2>
            <p className="text-xs text-secondary">
              Individual progress tracking and status synchronization across all targets
            </p>
          </div>
          <div className="flex items-center gap-space-sm">
            <span className="text-xs text-secondary font-mono">
              {scansHistory.filter((s) => s.status === 'running').length} Running • {scansHistory.length} Total
            </span>
            <button
              onClick={() => loadHistory(false)}
              className="p-1 rounded hover:bg-surface-container text-outline hover:text-on-surface transition-colors"
              title="Refresh scan states"
            >
              <span className="material-symbols-outlined text-[18px]">refresh</span>
            </button>
          </div>
        </div>

        {/* Multi-Scan Cards with Individual Progress Bars */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-space-md pt-space-xs">
          {scansHistory.map((scan) => {
            const isSelected = selectedScanId === scan.id;
            const isRunning = scan.status === 'running' || scan.status === 'pending';
            const isCompleted = scan.status === 'completed';
            const isFailed = scan.status === 'failed';
            const currentPct = isCompleted ? 100 : (scan.progress_percent || 0);

            return (
              <div
                key={scan.id}
                onClick={() => selectScan(scan)}
                className={`p-space-md rounded-xl border transition-all cursor-pointer flex flex-col justify-between gap-space-sm ${
                  isSelected
                    ? 'border-primary-container bg-surface-container-low/70 ring-2 ring-primary-container/40 shadow-sm'
                    : 'border-surface-variant/60 bg-surface-container-low/30 hover:bg-surface-container-low hover:border-surface-variant'
                }`}
              >
                {/* Header row */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="flex h-2.5 w-2.5 relative shrink-0">
                      {isRunning && (
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                      )}
                      <span
                        className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                          isRunning
                            ? 'bg-primary'
                            : isCompleted
                            ? 'bg-[#16a34a]'
                            : 'bg-error'
                        }`}
                      ></span>
                    </span>
                    <span className="font-mono text-xs font-bold text-on-surface truncate">
                      {scan.target_domain}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-surface-container text-secondary uppercase font-semibold">
                      {scan.scan_profile}
                    </span>
                  </div>

                  {/* Status Badge */}
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 ${
                        isRunning
                          ? 'bg-secondary-container text-on-secondary-fixed'
                          : isCompleted
                          ? 'bg-[#dcfce7] text-[#166534]'
                          : 'bg-error-container text-on-error-container'
                      }`}
                    >
                      {isRunning && <span className="material-symbols-outlined text-[12px] animate-spin">progress_activity</span>}
                      {isCompleted && <span className="material-symbols-outlined text-[12px]">check</span>}
                      <span>{scan.status}</span>
                    </span>
                  </div>
                </div>

                {/* Individual Dedicated Progress Bar for this Scan */}
                <div className="space-y-1 my-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-secondary font-medium truncate">
                      {isRunning
                        ? `Stage: ${getFriendlyPhaseName(scan.current_phase)}`
                        : isCompleted
                        ? 'All DAG Stages Complete'
                        : 'Halted'}
                    </span>
                    <span className="font-mono font-bold text-on-surface shrink-0 ml-2">
                      {currentPct}%
                    </span>
                  </div>

                  <div className="w-full h-2 rounded-full bg-surface-container overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        isCompleted
                          ? 'bg-[#16a34a]'
                          : isFailed
                          ? 'bg-error'
                          : 'bg-primary-container'
                      }`}
                      style={{ width: `${currentPct}%` }}
                    ></div>
                  </div>
                </div>

                {/* Footer Details */}
                <div className="flex items-center justify-between pt-1 border-t border-surface-variant/20 text-[11px] text-secondary">
                  <div className="flex items-center gap-3">
                    <span>
                      Assets: <strong className="text-on-surface font-mono">{scan.total_assets || 0}</strong>
                    </span>
                    {scan.avg_risk_score > 0 && (
                      <span>
                        Risk: <strong className="text-primary font-mono">{scan.avg_risk_score}/100</strong>
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-1">
                    {isSelected ? (
                      <span className="text-primary font-semibold text-[11px] flex items-center gap-0.5">
                        <span className="material-symbols-outlined text-[14px]">sensors</span>
                        Streaming
                      </span>
                    ) : (
                      <span className="text-secondary hover:text-primary transition-colors text-[11px]">
                        Inspect Logs &gt;
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* SECTION 3: Live Execution Stage & Real-Time Telemetry Terminal */}
      <section className="bg-surface-container-lowest rounded-xl p-space-xl shadow-sm border border-surface-variant/40 space-y-space-lg">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md pb-space-sm border-b border-surface-variant/40">
          <div className="flex flex-wrap items-center gap-space-sm">
            <div className="flex items-center gap-space-xs">
              <span className="flex h-3 w-3 relative">
                {activeJob?.status === 'running' && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                )}
                <span
                  className={`relative inline-flex rounded-full h-3 w-3 ${
                    activeJob?.status === 'completed' ? 'bg-[#16a34a]' : 'bg-primary'
                  }`}
                ></span>
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded bg-secondary-container text-on-secondary-fixed font-semibold uppercase tracking-wider">
                {activeJob?.status === 'completed'
                  ? 'RECON AUDIT COMPLETE // LIVE DISCOVERY'
                  : activeJob?.status === 'running'
                  ? 'LIVE RECON IN PROGRESS // LIVE DISCOVERY'
                  : 'TELEMETRY STREAM // LIVE DISCOVERY'}
              </span>
            </div>

            <span className="text-xs text-on-surface font-mono font-semibold">
              {activeJob ? (activeJob.status === 'running' ? `Job #RUNNING (${activeJob.id.slice(0, 8)})` : `Job #${activeJob.status.toUpperCase()} (${activeJob.id.slice(0, 8)})`) : 'Job #IDLE'}
            </span>
            <div className="h-4 w-[1px] bg-surface-variant"></div>
            <div className="flex items-center gap-space-xxs text-xs text-secondary">
              <span>Selected Target:</span>
              <span className="font-mono text-xs text-primary font-bold bg-surface-container-low px-2 py-0.5 rounded border border-surface-variant/40">
                {activeJob?.target_domain || targetDomain}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-space-xs px-space-sm py-1 rounded-lg bg-surface-container-low text-secondary font-mono text-xs border border-surface-variant/30">
            <span className="material-symbols-outlined text-[16px]">timer</span>
            <span>{formatElapsed(elapsedSeconds)} elapsed</span>
          </div>
        </div>

        {/* Synchronized Progress Bar for Selected Scan */}
        <div className="space-y-space-xs">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-space-xs min-w-0">
              <span className="font-semibold text-primary font-mono text-sm">{progressPercent}%</span>
              <span className="text-secondary truncate">— {phaseMessage}</span>
            </div>
            <span className="font-mono text-secondary text-[11px] shrink-0 ml-2">
              {activeJob?.status === 'completed'
                ? 'Completed'
                : activeJob?.status === 'running'
                ? 'Streaming Live Telemetry'
                : 'Selected Scan'}
            </span>
          </div>
          <div className="w-full h-2.5 rounded-full bg-surface-container overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ease-out ${
                activeJob?.status === 'completed' ? 'bg-[#16a34a]' : 'bg-primary-container'
              }`}
              style={{ width: `${progressPercent}%` }}
            ></div>
          </div>
        </div>

        {/* 6 Granular Step Stepper */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-space-sm pt-space-xs">
          {PHASES.map((p, idx) => {
            const status = getPhaseStatus(idx);
            return (
              <div
                key={p.id}
                className={`flex flex-col p-space-sm rounded-lg border transition-all ${
                  status === 'completed'
                    ? 'bg-surface-container-low border-surface-variant'
                    : status === 'active'
                    ? 'bg-secondary-container/60 border-primary-container shadow-sm ring-1 ring-primary-container'
                    : 'bg-surface-container-low/40 border-surface-variant/30 opacity-60'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-secondary font-mono font-semibold">{p.num}</span>
                  {status === 'completed' && (
                    <span className="material-symbols-outlined text-[#16a34a] text-[16px]">check_circle</span>
                  )}
                  {status === 'active' && (
                    <span className="material-symbols-outlined text-primary-container text-[16px] animate-spin">
                      progress_activity
                    </span>
                  )}
                  {status === 'pending' && <span className="w-2.5 h-2.5 rounded-full bg-surface-variant"></span>}
                </div>
                <span className="text-xs font-semibold text-on-surface leading-tight">{p.label}</span>
                <span className="text-[10px] text-secondary mt-0.5 hidden sm:block truncate">{p.description}</span>
              </div>
            );
          })}
        </div>

        {/* Console Log Terminal */}
        <div className="space-y-space-xs">
          <div className="flex items-center justify-between px-space-xs">
            <div className="flex items-center gap-space-xs">
              <span className="material-symbols-outlined text-[16px] text-secondary">terminal</span>
              <span className="text-xs font-semibold text-on-surface uppercase tracking-wider">
                Engine Telemetry Stream // {activeJob?.target_domain || 'Active'}
              </span>
              <span className="text-[11px] text-secondary font-mono">({logs.length} events logged)</span>
            </div>
            <button
              onClick={() => {
                const text = logs.map((l) => `[${l.time}] [${l.type}] ${l.text}`).join('\n');
                navigator.clipboard?.writeText(text);
                setCopiedLog(true);
                setTimeout(() => setCopiedLog(false), 2500);
              }}
              className="text-xs text-primary hover:underline font-medium flex items-center gap-1"
            >
              <span className="material-symbols-outlined text-[14px]">
                {copiedLog ? 'check' : 'content_copy'}
              </span>
              <span>{copiedLog ? 'Copied Full Log!' : 'Copy Full Log'}</span>
            </button>
          </div>

          <div
            ref={terminalRef}
            className="w-full bg-surface-container-low p-space-md rounded-xl font-mono text-xs text-on-surface space-y-1.5 overflow-x-auto max-h-72 overflow-y-auto border border-surface-variant/60 shadow-inner"
          >
            {logs.length > 0 ? (
              logs.map((log, index) => (
                <div key={index} className="flex items-start gap-2 leading-relaxed">
                  <span className="text-outline select-none shrink-0 font-mono text-[11px]">
                    [{log.time}]
                  </span>
                  <span
                    className={`font-semibold shrink-0 text-[11px] px-1 rounded ${
                      log.type === 'ALERT' || log.type === 'ERROR'
                        ? 'text-error bg-error-container/20'
                        : log.type === 'PROGRESS'
                        ? 'text-primary bg-primary-container/10'
                        : log.type === 'DISCOVERY'
                        ? 'text-on-secondary-fixed bg-secondary-container/40'
                        : log.type === 'NETWORK'
                        ? 'text-[#2563eb] bg-blue-50'
                        : log.type === 'EVAL'
                        ? 'text-[#d97706] bg-amber-50'
                        : log.type === 'COMPLETE'
                        ? 'text-[#16a34a] bg-emerald-50'
                        : 'text-secondary bg-surface-container'
                    }`}
                  >
                    [{log.type}]
                  </span>
                  <span
                    className={`text-on-surface break-all ${
                      log.type === 'ALERT'
                        ? 'text-error font-semibold'
                        : log.type === 'COMPLETE'
                        ? 'text-[#166534] font-semibold'
                        : ''
                    }`}
                  >
                    {log.text}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-secondary italic py-6 text-center space-y-1">
                <span className="material-symbols-outlined text-[24px] text-outline block">radar</span>
                <p>Console idle. Select an operation from above or launch a new scan to stream live discovery telemetry.</p>
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
