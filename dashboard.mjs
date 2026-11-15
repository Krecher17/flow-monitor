import {analyze, parseZeek} from './detector.mjs';
import {criticalHost, demoFlows, demoSplit} from './demo.mjs';

const $ = id => document.getElementById(id);
const number = new Intl.NumberFormat();
const time = new Intl.DateTimeFormat('en-GB', {timeZone: 'UTC', hour: '2-digit', minute: '2-digit'});
const dateTime = new Intl.DateTimeFormat('en-GB', {timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short'});
const percent = value => value === null ? '—' : `${(value * 100).toFixed(1)}%`;
let data, options, report, selected, source, replay;

function element(tag, content, className) {
  const node = document.createElement(tag);
  if (content !== undefined) node.textContent = content;
  if (className) node.className = className;
  return node;
}

function stop() {
  clearInterval(replay);
  replay = undefined;
  $('play').textContent = '▶ Play replay';
}

function load(flows, settings, name, index) {
  const result = analyze(flows, {...settings, threshold: Number($('threshold').value)});
  stop();
  [data, options, source, report] = [flows, settings, name, result];
  selected = Math.min(index, report.windows.length - 1);
  render();
}

function demo() {
  load(demoFlows(), {baselineEnd: demoSplit, critical: [criticalHost]}, 'Synthetic replay', 2);
}

function render() {
  const window = report.windows[selected];
  const alerts = window.edges.filter(edge => edge.alert);
  $('source').textContent = source;
  $('threshold-value').value = report.threshold;
  const stats = [
    ['Flows this window', number.format(window.flows)],
    ['Directed host pairs', number.format(window.edges.length)],
    ['Alerts this window', number.format(alerts.length)],
    ['Handshake metadata', percent(report.tls / report.total)]
  ];
  $('stats').replaceChildren(...stats.map(([label, value]) => {
    const card = element('div', undefined, 'stat');
    card.append(element('span', label), element('strong', value));
    return card;
  }));
  $('split').textContent = `${number.format(report.baseline)} baseline flows · cutoff ${dateTime.format(report.split * 1000)} UTC · 15-minute windows`;
  $('windows').replaceChildren(...report.windows.map((capture, index) => {
    const count = capture.edges.filter(edge => edge.alert).length;
    const button = element('button', undefined, count ? 'has-alerts' : undefined);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(selected === index));
    button.title = `${dateTime.format(capture.start * 1000)} UTC`;
    button.append(element('strong', time.format(capture.start * 1000)),
      element('span', `${count} ${count === 1 ? 'alert' : 'alerts'}`));
    button.onclick = () => { stop(); selected = index; render(); };
    return button;
  }));
  if (!alerts.length) $('alerts').replaceChildren(element('p', 'No pairs crossed the threshold in this window.', 'empty'));
  else $('alerts').replaceChildren(...alerts.map((edge, index) => {
    const item = element('details');
    item.open = index === 0;
    const summary = element('summary');
    const pair = element('span');
    pair.append(element('strong', `${edge.src} → ${edge.dst}`),
      element('small', `${edge.count} ${edge.count === 1 ? 'flow' : 'flows'} · ${[...new Set(edge.signals.map(signal => signal.layer))].join(' / ')}`));
    summary.append(pair, element('b', edge.score, 'score'));
    const reasons = element('ul');
    edge.signals.forEach(signal => reasons.append(element('li', `+${signal.points}  ${signal.reason}`)));
    const meta = [edge.metadata.sni, edge.metadata.versions.join(', '),
      edge.metadata.bytes === undefined ? '' : `${number.format(edge.metadata.bytes)} bytes`,
      edge.metadata.duration === undefined ? '' : `${edge.metadata.duration.toFixed(2)}s mean duration`,
      edge.metadata.outboundShare === undefined ? '' : `${percent(edge.metadata.outboundShare)} outbound bytes`].filter(Boolean);
    item.append(summary, reasons);
    if (meta.length) item.append(element('p', meta.join(' · '), 'metadata'));
    return item;
  }));
  graph(window.edges);
  metrics();
}

function graph(edges) {
  const canvas = $('graph');
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const visible = new Set();
  const shown = edges.filter(({src, dst}) => {
    const missing = new Set([src, dst].filter(host => !visible.has(host)));
    if (visible.size + missing.size > 24) return false;
    missing.forEach(host => visible.add(host));
    return true;
  });
  $('graph-caption').textContent = `${visible.size} hosts · ${shown.length} of ${edges.length} directed links shown`;
  const origins = new Set(shown.map(edge => edge.src));
  const targets = new Set(shown.map(edge => edge.dst));
  const lanes = [[], [], []];
  [...visible].sort().forEach(host => lanes[origins.has(host) ? (targets.has(host) ? 1 : 0) : 2].push(host));
  const positions = new Map();
  lanes.forEach((hosts, col) => hosts.forEach((host, row) => positions.set(host, {
    x: 110 + col * 250, y: 25 + (h - 50) * (row + 0.5) / hosts.length
  })));
  const highlighted = new Set(shown.filter(edge => edge.alert).flatMap(edge => [edge.src, edge.dst]));
  for (const edge of [...shown].reverse()) {
    const a = positions.get(edge.src);
    const b = positions.get(edge.dst);
    const angle = Math.atan2(b.y - a.y, b.x - a.x);
    const x = b.x - 9 * Math.cos(angle);
    const y = b.y - 9 * Math.sin(angle);
    ctx.strokeStyle = ctx.fillStyle = edge.alert ? '#ff996c' : '#375267';
    ctx.lineWidth = edge.alert ? 2.5 : 1;
    ctx.beginPath();
    if (edge.src === edge.dst) {
      ctx.arc(a.x + 9, a.y - 9, 10, 0, Math.PI * 2);
      ctx.stroke();
      continue;
    }
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(x, y);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x - 8 * Math.cos(angle - 0.45), y - 8 * Math.sin(angle - 0.45));
    ctx.lineTo(x - 8 * Math.cos(angle + 0.45), y - 8 * Math.sin(angle + 0.45));
    ctx.fill();
  }
  ctx.font = '13px monospace';
  for (const [host, {x, y}] of positions) {
    ctx.fillStyle = highlighted.has(host) ? '#ff996c' : '#57d4bf';
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, Math.PI * 2);
    ctx.fill();
    const label = options.critical.includes(host) ? `${host} ★` : host;
    const width = Math.min(ctx.measureText(label).width, 145);
    ctx.fillStyle = '#10202e';
    ctx.fillRect(x + 9, y - 9, width + 7, 18);
    ctx.fillStyle = '#d8e8f5';
    ctx.fillText(label, x + 12, y + 4, 145);
  }
}

function metrics() {
  $('evaluation-note').textContent = report.metrics
    ? 'Labeled synthetic observation windows · one sample per directed host pair per window'
    : 'The imported capture has no ground-truth labels.';
  if (!report.metrics) {
    $('metrics').textContent = '';
    return;
  }
  const table = element('table');
  const header = table.createTHead().insertRow();
  for (const text of ['Detector', 'Precision', 'Recall', 'False-positive rate', 'TP', 'FP', 'FN', 'TN']) {
    const cell = element('th', text);
    cell.scope = 'col';
    header.append(cell);
  }
  const body = table.createTBody();
  for (const [name, score] of [['Weighted signals', report.metrics.alert], ['TLS policy rule', report.metrics.rule]]) {
    const row = body.insertRow();
    for (const value of [name, percent(score.precision), percent(score.recall), percent(score.fpr),
      score.tp, score.fp, score.fn, score.tn]) row.insertCell().textContent = value;
  }
  $('metrics').replaceChildren(table);
}

$('threshold').oninput = () => {
  report = analyze(data, {...options, threshold: Number($('threshold').value)});
  render();
};
$('play').onclick = () => {
  if (replay) { stop(); return; }
  selected = 0;
  $('play').textContent = 'Ⅱ Pause replay';
  render();
  replay = setInterval(() => {
    if (selected + 1 >= report.windows.length) { stop(); return; }
    selected++;
    render();
  }, 1300);
};
$('demo').onclick = demo;
$('open-import').onclick = () => $('import').showModal();
$('close-import').onclick = () => $('import').close();
$('import-form').onsubmit = async event => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  $('import-error').textContent = '';
  try {
    const files = ['conn', 'ssl', 'quic'].map(id => $(id).files[0]);
    if (files.reduce((sum, file) => sum + (file?.size ?? 0), 0) > 15_000_000) {
      throw new Error('Choose logs totaling 15 MB or less.');
    }
    const texts = await Promise.all(files.map(file => file?.text() ?? ''));
    const cutoff = $('cutoff').value;
    load(parseZeek(...texts), {baselineEnd: cutoff ? Date.parse(`${cutoff}Z`) / 1000 : undefined,
      critical: $('critical').value.split(',').map(host => host.trim()).filter(Boolean)}, files[0].name, 0);
    $('import').close();
  } catch (error) {
    $('import-error').textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

demo();
