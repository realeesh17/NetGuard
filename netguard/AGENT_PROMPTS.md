# NetGuard — Agent Build Prompts (Enhanced Version)

Paste each prompt into a fresh agent session for that phase, in order.
Each assumes the repo scaffold and `PROJECT_PLAN.md` are already in the repo root.

---

## Prompt 1 — Core (DB + Event Bus)

```
Read PROJECT_PLAN.md in this repo, specifically section 3.1 (Shared Core).
Build out core/ with:
- core/models.py: SQLAlchemy models for Event, PacketLog, PhishingScan,
  FirewallRule, and FirewallDecision, matching the schema details in the plan.
- core/db.py: SQLite engine + session setup, a get_session() helper context manager,
  and an init_db() function that creates all tables.
- core/config.py: config settings loaded from env vars with sensible defaults,
  including interface name, DB path, ML model paths, and detection thresholds.
- core/events.py: a single log_event(source, severity, summary, raw_data)
  function that writes to the Event table and supports pushing to a WebSocket/event-loop queue if needed.
Add a tests/test_core.py that creates an in-memory DB, logs a couple of
events, and asserts they round-trip correctly.
Do not touch sniffer/, phishing/, firewall/, or dashboard/ yet.
```

---

## Prompt 2 — Firewall Simulator (synthetic mode first)

```
Read PROJECT_PLAN.md, section 3.4 (Firewall Simulator). core/ already exists
with models.py, db.py, events.py — use core.events.log_event for every
firewall decision, don't write to the DB directly.

Build firewall/:
- engine.py: FirewallRule-driven engine with ordered, first-match-wins
  semantics (action: allow|deny, src_ip, dst_port, protocol, with support
  for CIDR ranges and port ranges). Load rules from the DB via core.models.
- simulate.py: a synthetic traffic generator that produces randomized
  packet-like dicts (src_ip, dst_ip, dst_port, protocol) and runs them
  through engine.py, logging each decision via core.events.log_event with
  source="firewall".
- visualize_data.py: a function that aggregates recent FirewallDecision rows
  into a structure suitable for a Sankey-style "allowed vs blocked, by which
  rule matched" diagram (return plain dicts/lists, no plotting library).

Leave a clear extension point (a function signature/comment) in simulate.py
for a future "live mode" that will consume real packets from sniffer/ instead
of synthetic ones — don't build that yet.

Add tests/test_firewall.py covering: first-match-wins ordering, CIDR
matching, and that decisions get logged.
```

---

## Prompt 3 — Packet Sniffer

```
Read PROJECT_PLAN.md, section 3.2 (Packet Sniffer). core/ exists and is
stable — use core.events.log_event with source="sniffer" for all flags.

Build sniffer/:
- capture.py: scapy-based sniff() running on a background thread, accepting
  a BPF filter string (protocol/port) and an interface name from
  core.config. Provide start()/stop() functions and a thread-safe queue or
  callback that downstream code can consume captured packets from.
- rules.py: rule-based detectors — port scan / SYN flood (high SYN count,
  low SYN-ACK ratio from one src IP within a rolling window), abnormal
  packet size, DNS tunneling heuristics (long or high-entropy subdomains),
  and a static IP blacklist check.
- features.py: per-src-IP rolling window feature extraction — packet rate,
  count of unique dst ports touched, average payload size, protocol mix —
  as a function that returns a feature vector suitable for scikit-learn.
- anomaly.py: load a pre-trained IsolationForest (path from core.config;
  handle the "no model trained yet" case gracefully) and score incoming
  feature vectors. If no model exists, skip anomaly scoring but keep
  rule-based detection working.

Every rule-based flag AND every anomaly-flagged window should call
core.events.log_event, tagging raw_data with which detector fired.

Important: this needs root/admin privileges to run scapy.sniff() on a real
interface. Document this clearly in a comment at the top of capture.py and
in a "Running the sniffer" section you add to README.md. Do not attempt to
work around the privilege requirement.

Add tests/test_sniffer_rules.py that feeds synthetic packet-like objects
(not live capture) into rules.py and features.py and asserts the detectors
fire correctly. Do not attempt live capture in tests.
```

---

## Prompt 4 — Wire Sniffer into Firewall (live mode)

```
Read PROJECT_PLAN.md. core/, firewall/, and sniffer/ all exist and have
passing tests. Now connect them:

In firewall/simulate.py, add a live mode that subscribes to packets from
sniffer/capture.py (via whatever queue/callback mechanism capture.py
exposes), converts each captured packet into the same dict shape used by
the synthetic generator, and runs it through engine.py in real time,
logging decisions exactly as synthetic mode does.

Add a config flag (core.config) to switch between synthetic and live mode.
Update tests/test_firewall.py with a test that feeds a fake packet through
the live-mode entry point (mock the sniffer queue, don't require an actual
network interface).
```

---

## Prompt 5 — Phishing Page Detector

```
Read PROJECT_PLAN.md, section 3.3 (Phishing Page Detector). core/ exists and
is stable — use core.events.log_event with source="phishing" for every
completed scan.

Build phishing/:
- fetch.py: requests-based fetch with timeout, follow redirects, and
  capture the full redirect chain as a list of URLs.
- cert.py: TLS cert inspection (issuer, validity window, self-signed check)
  for https:// URLs, using ssl/pyopenssl. Handle non-https and connection
  failures gracefully (that itself is a signal, not a crash).
- domain.py: python-whois lookup for domain age, registrar, expiry date.
  Add basic rate-limiting/backoff since many registrars throttle automated
  WHOIS queries.
- content.py: BeautifulSoup-based parsing for: form action targets pointing
  off-domain, presence of password input fields, brand-keyword-in-text vs
  domain mismatch, favicon hash mismatch, and a simple obfuscated-JS
  heuristic (e.g. unusually high non-alphanumeric density in inline
  <script> blocks).
- analyze.py: orchestrates fetch → cert → domain → content, assembles a
  feature vector, and (if a trained model exists at the path in
  core.config) runs it through the classifier from ml/models/; otherwise
  falls back to a simple weighted rule-based score. Returns
  {score, verdict, reasons: [...]} — reasons should be human-readable
  strings tied to specific signals found, not just feature names.

Add tests/test_phishing.py using mocked requests/whois/ssl responses (do
not make real network calls in tests) covering at least: a clean site, a
site with an off-domain form action, and a very young domain.
```

---

## Prompt 6 — ML Training Scripts

```
Read PROJECT_PLAN.md, sections 3.2, 3.3, and ml/ directory. sniffer/ and
phishing/ are built and have feature-extraction functions (sniffer/features.py,
phishing/analyze.py's feature vector step) — reuse those, don't
re-implement feature extraction here.

Build ml/training/:
- train_anomaly_model.py: loads/generates a features CSV (rows =
  sniffer/features.py output over sample or synthetic traffic), trains an
  IsolationForest, saves it to ml/models/anomaly_model.pkl via joblib.
- train_phishing_classifier.py: loads data/datasets/ CSVs (expects a
  PhishTank-style phishing URL list and a Tranco-style legit domain list —
  document the expected CSV columns at the top of the file), runs each
  URL through phishing/analyze.py's feature-extraction step, trains a
  LogisticRegression (with a commented-out RandomForestClassifier
  alternative), saves to ml/models/phishing_model.pkl via joblib, and
  prints precision/recall/F1 on a held-out split.

Do not fabricate a dataset — if data/datasets/ is empty, the script should
fail with a clear message telling the user what file(s) to place there and
what columns are expected, not silently generate fake data and pretend it's
real training data.
```

---

## Prompt 7 — Dashboard (Cyber-HUD)

```
Read PROJECT_PLAN.md, section 1.1 and 3.5 (Dashboard). All of core/, sniffer/,
firewall/, and phishing/ exist and are functional.

Build dashboard/:
- app.py: Flask + Flask-SocketIO app.
- Routes/pages:
  - "/" : unified live event feed — poll or push (via socketio) recent
    core.models.Event rows across all three sources, newest first, with
    source/severity badges.
  - "/sniffer" : start/stop capture controls (calling sniffer/capture.py),
    live view of flagged packets and anomaly scores.
  - "/phishing" : URL submission form, calls phishing/analyze.py, renders
    the score/verdict/reasons.
  - "/firewall" : rule list editor (add/remove/reorder FirewallRule rows)
    and the flow visualization from firewall/visualize_data.py.
- templates/ + static/: Use a dark glassmorphic Cyber-HUD design (deep blue background,
  semi-transparent cards, glowing borders, and neon indicators). Use Chart.js/custom SVG
  for traffic graphs and protocol distributions. On the firewall page, build a beautiful
  interactive SVG Sankey/Flow Visualizer with animated neon dots traveling along path lines.

Dashboard must only read/write via core.models — no direct DB access
bypassing core.

Add a top-level run.py that calls core.db.init_db() then starts the
dashboard app.
```
