const WINDOW = 900;
const mean = values => values.reduce((sum, value) => sum + value, 0) / values.length;
const edgeKey = ({src, dst}) => JSON.stringify([src, dst]);
const increment = (counts, key) => counts.set(key, (counts.get(key) ?? 0) + 1);

export function parseZeek(conn, ssl = '', quic = '') {
  function rows(input, name) {
    return input.split('\n').flatMap((line, index) => {
      if (!line.trim()) return [];
      try {
        const record = JSON.parse(line);
        if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error();
        return [record];
      } catch {
        throw new Error(`${name}, line ${index + 1}: expected a Zeek JSON object.`);
      }
    });
  }
  const tls = new Map(
    [...rows(ssl, 'SSL log'), ...rows(quic, 'QUIC log')].filter(row => row.uid)
      .map(row => [row.uid, row])
  );
  const flows = rows(conn, 'Connection log').map((row, index) => {
    if (!Number.isFinite(row.ts) || typeof row['id.orig_h'] !== 'string' ||
        typeof row['id.resp_h'] !== 'string') {
      throw new Error(`Connection record ${index + 1} needs ts, id.orig_h and id.resp_h.`);
    }
    const handshake = tls.get(row.uid) ?? {};
    return {
      ts: row.ts, src: row['id.orig_h'], dst: row['id.resp_h'],
      port: row['id.resp_p'], proto: row.proto, duration: row.duration,
      sent: row.orig_bytes, received: row.resp_bytes,
      packets: Number.isFinite(row.orig_pkts) && Number.isFinite(row.resp_pkts)
        ? row.orig_pkts + row.resp_pkts : undefined,
      version: handshake.version, cipher: handshake.cipher, group: handshake.curve,
      sni: handshake.server_name, resumed: handshake.resumed,
      fingerprint: handshake.ja4 ? `JA4 ${handshake.ja4}` : handshake.ja3 ? `JA3 ${handshake.ja3}` : undefined,
      selfIssued: Boolean(handshake.subject && handshake.subject === handshake.issuer)
    };
  });
  if (!flows.length) throw new Error('The connection log is empty.');
  return flows;
}

function timing(flows) {
  const times = [...new Set(flows.map(flow => flow.ts))];
  if (times.length < 7) return null;
  const gaps = times.slice(1).map((time, index) => time - times[index]);
  const period = mean(gaps);
  if (period < 5) return null;
  const cv = Math.sqrt(mean(gaps.map(gap => (gap - period) ** 2))) / period;
  if (cv > 0.18) return null;
  // Normalized Fourier amplitude at the candidate cadence.
  const phases = times.map(time => 2 * Math.PI * (time - times[0]) / period);
  const coherence = Math.hypot(mean(phases.map(Math.cos)), mean(phases.map(Math.sin)));
  const bins = new Map();
  gaps.forEach(gap => increment(bins, Math.floor(gap / (period * 0.1))));
  const entropy = [...bins.values()].reduce((sum, count) => {
    const p = count / gaps.length;
    return sum - p * Math.log2(p);
  }, 0);
  return {period, cv, coherence, entropy};
}

function groupBy(items, keyOf) {
  const groups = new Map();
  for (const item of items) {
    const key = keyOf(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

function windowGraph(flows) {
  const edges = groupBy(flows, edgeKey);
  const outgoing = new Map();
  for (const [key, [{src}]] of edges) {
    if (!outgoing.has(src)) outgoing.set(src, []);
    outgoing.get(src).push(key);
  }
  return {edges, outgoing};
}

const legacy = flow => /^(SSL(?:v?2|v?3)?|TLSv?1(?:[._]?0|[._]?1)?)$/i.test(flow.version ?? '');
const weakCipher = flow => /(?:^|_)(?:NULL|RC4|3DES|EXPORT)(?:_|$)/i.test(flow.cipher ?? '');
const policy = flow => legacy(flow) || weakCipher(flow);

export function analyze(input, {baselineEnd, critical = [], threshold = 60} = {}) {
  const flows = [...input].sort((a, b) => a.ts - b.ts);
  if (!flows.length) throw new Error('At least one flow is required.');
  const origin = flows[0].ts;
  const split = baselineEnd ?? origin + Math.max(WINDOW, Math.floor((flows.at(-1).ts - origin) / WINDOW / 3) * WINDOW);
  const baseline = flows.filter(flow => flow.ts < split);
  const observed = flows.filter(flow => flow.ts >= split);
  if (!baseline.length || !observed.length) {
    throw new Error('The time split needs baseline and observation flows. Use a capture spanning more than 15 minutes or set an earlier cutoff.');
  }
  const knownEdges = new Set(baseline.map(edgeKey));
  const fingerprints = new Map();
  const destinationGroups = new Map();
  for (const flow of baseline) {
    if (flow.fingerprint) increment(fingerprints, flow.fingerprint);
    if (flow.group) {
      if (!destinationGroups.has(flow.dst)) destinationGroups.set(flow.dst, new Set());
      destinationGroups.get(flow.dst).add(flow.group);
    }
  }
  const maxFanout = new Map();
  for (const rows of groupBy(baseline, flow => Math.floor((flow.ts - origin) / WINDOW)).values()) {
    for (const [src, edges] of windowGraph(rows).outgoing) {
      maxFanout.set(src, Math.max(maxFanout.get(src) ?? 0, edges.length));
    }
  }
  const windows = [];
  for (const [index, rows] of groupBy(observed, flow => Math.floor((flow.ts - split) / WINDOW))) {
    const {edges, outgoing} = windowGraph(rows);
    const newCounts = new Map();
    const newPredecessors = new Map();
    for (const [key, [{src, dst}]] of edges) {
      if (knownEdges.has(key)) continue;
      increment(newCounts, src);
      if (!newPredecessors.has(dst)) newPredecessors.set(dst, []);
      newPredecessors.get(dst).push(src);
    }
    const results = [];
    for (const [key, group] of edges) {
      const {src, dst} = group[0];
      const signals = [];
      const add = (layer, points, reason) => signals.push({layer, points, reason});
      const cadence = timing(group);
      if (cadence?.coherence >= 0.75) {
        add('Timing', 48, `${cadence.period.toFixed(1)}s cadence · ${(cadence.cv * 100).toFixed(1)}% gap CV · Fourier coherence ${cadence.coherence.toFixed(2)} · entropy ${cadence.entropy.toFixed(2)} bits`);
      }
      const fingerprint = group.find(flow => flow.fingerprint && !fingerprints.has(flow.fingerprint))?.fingerprint;
      if (fingerprint && fingerprints.size) add('TLS', 22, `Fingerprint absent from baseline (${fingerprint})`);
      if (group.some(policy)) add('TLS', 45, 'Deprecated TLS version or weak negotiated cipher');
      if (group.some(flow => flow.selfIssued)) add('TLS', 12, 'Certificate subject and issuer match');
      const knownGroups = destinationGroups.get(dst);
      const unusualGroup = group.find(flow => flow.group && knownGroups && !knownGroups.has(flow.group))?.group;
      if (unusualGroup) add('TLS', 18, `Group ${unusualGroup} absent from the destination baseline`);
      const resumed = group.filter(flow => flow.resumed === true).length;
      if (resumed >= 8 && resumed / group.length >= 0.8) add('TLS', 10, `${resumed}/${group.length} flows report TLS resumption`);
      if (!knownEdges.has(key)) {
        add('Graph', 14, 'Directed host pair absent from baseline');
        const fanout = outgoing.get(src).length;
        const usual = maxFanout.get(src) ?? 0;
        const novel = newCounts.get(src);
        if (novel >= 3 && fanout >= usual + 3) {
          add('Graph', 34, `${novel} new destinations in 15 minutes · ${fanout} total vs baseline peak ${usual}`);
        }
        if (critical.includes(dst)) {
          add('Graph', 24, 'New connection to a configured critical host');
          const prior = newPredecessors.get(src)?.find(host => host !== src && host !== dst &&
            edges.get(edgeKey({src: host, dst: src}))[0].ts < group.at(-1).ts);
          if (prior) add('Graph', 24, `Two new directed hops in this window · ${prior} → ${src} → ${dst}`);
        }
        const next = outgoing.get(dst)?.find(candidate => {
          const [hop] = edges.get(candidate);
          return !knownEdges.has(candidate) && hop.dst !== src && hop.dst !== dst &&
            critical.includes(hop.dst) && edges.get(candidate).at(-1).ts > group[0].ts;
        });
        if (next) add('Graph', 24, `Precedes a new hop to critical host ${edges.get(next)[0].dst} in this window`);
      }
      const score = Math.min(100, signals.reduce((sum, signal) => sum + signal.points, 0));
      const durations = group.map(flow => flow.duration).filter(Number.isFinite);
      const counters = group.filter(flow => Number.isFinite(flow.sent) && Number.isFinite(flow.received));
      const sent = counters.reduce((sum, flow) => sum + flow.sent, 0);
      const received = counters.reduce((sum, flow) => sum + flow.received, 0);
      results.push({src, dst, count: group.length, score, signals, alert: score >= threshold,
        rule: group.some(policy), truth: group.some(flow => flow.label === 'anomaly'),
        metadata: {
          sni: group.find(flow => flow.sni)?.sni,
          versions: [...new Set(group.map(flow => flow.version).filter(Boolean))],
          bytes: group.some(flow => Number.isFinite(flow.sent) || Number.isFinite(flow.received))
            ? group.reduce((sum, flow) => sum + (flow.sent ?? 0) + (flow.received ?? 0), 0) : undefined,
          duration: durations.length ? mean(durations) : undefined,
          outboundShare: sent + received > 0 ? sent / (sent + received) : undefined
        }
      });
    }
    results.sort((a, b) => b.score - a.score);
    windows.push({start: split + index * WINDOW, flows: rows.length, edges: results});
  }
  return {windows, baseline: baseline.length, total: flows.length, split, threshold,
    tls: flows.filter(flow => flow.version || flow.fingerprint || flow.cipher || flow.group || flow.sni ||
      typeof flow.resumed === 'boolean' || flow.selfIssued).length,
    metrics: observed.every(flow => flow.label === 'benign' || flow.label === 'anomaly')
      ? evaluate(windows.flatMap(window => window.edges)) : null};
}

function evaluate(edges) {
  return Object.fromEntries(['alert', 'rule'].map(key => {
    const tp = edges.filter(edge => edge.truth && edge[key]).length;
    const fp = edges.filter(edge => !edge.truth && edge[key]).length;
    const fn = edges.filter(edge => edge.truth && !edge[key]).length;
    const tn = edges.length - tp - fp - fn;
    const ratio = (a, b) => b ? a / b : null;
    return [key, {tp, fp, fn, tn, precision: ratio(tp, tp + fp),
      recall: ratio(tp, tp + fn), fpr: ratio(fp, fp + tn)}];
  }));
}
