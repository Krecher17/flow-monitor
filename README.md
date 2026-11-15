# Flow Monitor

Flow Monitor scores network metadata in 15-minute windows and explains alerts per directed host pair. It runs locally with Node.js and a modern browser. There are no package dependencies.

## Run the demo

```powershell
node server.mjs
```

Open [the dashboard](http://127.0.0.1:4173). The initial window contains a roughly 60-second beacon and a two-hop anomaly leading to the configured critical host. Open an alert to inspect its point contributions or select **Play replay** to step through the synthetic timeline. The server binds to loopback and serves static files. The browser reads imports into memory without uploading them.

## Analyze a capture

Generate newline-delimited JSON logs from an authorized capture with Zeek:

```sh
zeek -r capture.pcap LogAscii::use_json=T
```

Use **Import Zeek logs** and select `conn.log` plus `ssl.log` and `quic.log` when available. The importer joins these by UID. Choose a UTC cutoff that separates a trusted early baseline from later traffic. The automatic cutoff uses approximately the earliest third of the capture span, rounded down to a 15-minute boundary with a 15-minute minimum. Supply critical host IPs to enable path scoring. Inputs are limited to 15 MB combined. See the [Zeek log documentation](https://docs.zeek.org/en/current/tutorial/logs.html) and [TLS field reference](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html).

## Detection and interpretation

- Flow records include endpoints, transport, direction byte totals, duration and packet counts when exported. Timing is derived from flow start timestamps. Packet-size distributions and packet-level inter-arrival times require additional exporter fields.
- Handshake checks cover legacy versions, weak negotiated ciphers, unseen JA3/JA4 and destination key-exchange groups, matching certificate subject and issuer, and high resumption counts. Visibility depends on the exporter and on-wire protocol. Fingerprints must already be in the logs. Matching subject and issuer is a heuristic and does not verify a signature or trust chain. A resumption alert indicates observed frequency.
- Beaconing candidates need at least seven distinct timestamps and a mean gap of at least five seconds. The detector measures interval coefficient of variation and entropy and computes normalized Fourier coherence at the estimated cadence.
- The directed graph compares edges and host fan-out to the baseline. It also checks for temporally ordered two-hop paths to critical hosts. The graph view prioritizes high-scoring links and shows up to 24 hosts per window.
- Signal points add up to a score capped at 100. The default threshold is 60. An alert is a heuristic lead for analyst review. The baseline profiles use only preceding flow records and do not require attack labels. The dashboard does not consume packets, application payloads, or decryption keys. IPs, hostnames and fingerprints are still sensitive metadata.

## Evaluation

The built-in demo uses generated metadata. Two benign windows build the baseline and four later windows provide evaluation samples. Each sample is one directed pair in one window. A pair is positive if it contains at least one labeled anomaly.

| Detector at default settings | Precision | Recall | False-positive rate | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Weighted detector | 100% | 57.1% | 0% | 4 | 0 | 3 | 57 |
| Legacy TLS / weak cipher rule | 0% | 0% | 1.8% | 0 | 1 | 7 | 56 |

The weighted detector misses three fan-out pairs below threshold. This fixture tests the behavior of the pipeline. Measuring zero-day generalization and comparing against Snort require independent labeled captures and actual Snort output. Imported Zeek logs run in exploratory mode without ground-truth metrics. The current implementation uses batch windows and replay.
