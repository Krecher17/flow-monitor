export const criticalHost = '10.14.8.10';
const START = Date.UTC(2026, 10, 15, 8, 0) / 1000;
export const demoSplit = START + 1800;

export function demoFlows() {
  let seed = 34216;
  const random = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 4294967296;
  };
  const flows = [];
  function add(offset, src, dst, extra = {}) {
    flows.push({
      ts: START + offset, src, dst, port: 443, proto: 'tcp',
      version: 'TLSv13', group: 'x25519', fingerprint: 'JA4 demo_browser',
      sent: Math.round(80 + random() * 900), received: Math.round(500 + random() * 9000),
      duration: 0.06 + random() * 2, label: 'benign', ...extra
    });
  }
  const hosts = ['10.14.1.21', '10.14.1.34', '10.14.1.51', '10.14.2.12', '10.14.2.19', '10.14.3.7'];
  const services = ['192.0.2.14', '198.51.100.32', '203.0.113.8', '10.14.6.5'];
  for (let window = 0; window < 6; window++) {
    for (const [index, src] of hosts.entries()) {
      for (let count = 0; count < 18; count++) {
        add(window * 900 + random() * 899, src, services[(index + count % 2) % services.length]);
      }
    }
    add(window * 900 + 180, hosts[5], criticalHost);
    for (let tick = 0; tick < 10; tick++) add(window * 900 + 35 + tick * 75, hosts[5], services[0]);
  }
  for (let window = 3; window <= 4; window++) {
    for (let tick = 0; tick < 13; tick++) {
      add(window * 900 + 32 + tick * 60 + random() * 3, hosts[1], '203.0.113.77',
        {label: 'anomaly', fingerprint: 'JA4 demo_unseen', sni: 'sync.example.test'});
    }
  }
  const pivot = '10.14.4.55';
  add(3650, hosts[0], pivot, {label: 'anomaly', group: 'secp384r1', fingerprint: 'JA4 demo_pivot'});
  add(3670, pivot, criticalHost, {label: 'anomaly'});
  add(3690, pivot, '10.14.4.56', {label: 'anomaly'});
  add(3730, pivot, '10.14.4.57', {label: 'anomaly'});
  add(3770, pivot, '10.14.4.58', {label: 'anomaly'});
  add(120, hosts[5], pivot);
  add(4860, hosts[4], '192.0.2.88', {version: 'TLSv10'});
  return flows;
}
