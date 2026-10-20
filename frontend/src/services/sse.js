/**
 * AEGIS Server-Sent Events (SSE) Client
 * Subscribes to live scan telemetry via GET /api/events/:scanId
 * Listens to both custom named events (EventSource.addEventListener)
 * and generic message events with full JSON parsing and error recovery.
 */

export function subscribeScanEvents(scanId, callbacks = {}) {
  const {
    onMessage,
    onProgress,
    onAssetDiscovered,
    onPortDiscovered,
    onVulnDiscovered,
    onRiskScored,
    onCompleted,
    onFailed,
    onError,
  } = callbacks;

  const url = `/api/events/${encodeURIComponent(scanId)}`;
  const eventSource = new EventSource(url);

  const dispatchEvent = (eventType, rawPayload) => {
    let data = {};
    if (typeof rawPayload === 'string') {
      try {
        data = JSON.parse(rawPayload);
      } catch (err) {
        console.warn('[SSE] Error parsing raw JSON:', rawPayload, err);
        data = { raw: rawPayload };
      }
    } else if (typeof rawPayload === 'object' && rawPayload !== null) {
      data = rawPayload;
    }

    const resolvedType = eventType || data.type || data.event || 'message';

    if (onMessage) {
      onMessage({ ...data, event: resolvedType, type: resolvedType });
    }

    switch (resolvedType) {
      case 'scan_progress':
        if (onProgress) onProgress(data);
        break;
      case 'asset_discovered':
        if (onAssetDiscovered) onAssetDiscovered(data);
        break;
      case 'port_discovered':
        if (onPortDiscovered) onPortDiscovered(data);
        break;
      case 'vulnerability_discovered':
        if (onVulnDiscovered) onVulnDiscovered(data);
        break;
      case 'risk_scored':
        if (onRiskScored) onRiskScored(data);
        break;
      case 'scan_completed':
        if (onCompleted) onCompleted(data);
        break;
      case 'scan_failed':
        if (onFailed) onFailed(data);
        break;
      default:
        break;
    }
  };

  // 1. Generic message handler
  eventSource.onmessage = (event) => {
    dispatchEvent(null, event.data);
  };

  // 2. Named SSE events handler (Standard RFC 8895 browser EventSource)
  const namedEvents = [
    'scan_progress',
    'asset_discovered',
    'port_discovered',
    'vulnerability_discovered',
    'risk_scored',
    'scan_completed',
    'scan_failed',
  ];

  namedEvents.forEach((eventName) => {
    eventSource.addEventListener(eventName, (event) => {
      dispatchEvent(eventName, event.data);
    });
  });

  eventSource.onerror = (err) => {
    console.warn(`[SSE] EventSource closed or errored for scan ${scanId}`);
    if (onError) onError(err);
  };

  // Return unsubscribe cleanup function
  return () => {
    eventSource.close();
  };
}
