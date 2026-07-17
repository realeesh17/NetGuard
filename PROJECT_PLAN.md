# NetGuard — Advanced Unified Security Dashboard

Unified security dashboard containing: **Packet Sniffer (ML-powered Anomaly Scoring) + Phishing Page Detector + Interactive Firewall Simulator**. All sharing a unified Flask/SocketIO backend, an SQLite database, and an ML detection layer.

---

## 1. Premium Architecture & Design System

### 1.1 Cyber-HUD Design Guidelines
The interface is designed to feel like an advanced Security Operations Center (SOC) dashboard.
- **Color Palette:**
  - Background: Deep Void Blue (`#080c14` / `#0b0f19`)
  - Cards: Semi-transparent Slate Glass (`rgba(30, 41, 59, 0.45)` with `backdrop-filter: blur(16px)`)
  - Borders: Cyber-Teal Glow (`rgba(0, 242, 254, 0.2)` / `#00f2fe`)
  - Safe / Allow: Emerald Aurora (`#10b981` / `#059669`)
  - Warning / Alert: Solar Amber (`#f59e0b` / `#d97706`)
  - Critical / Block: Neon Crimson (`#ef4444` / `#dc2626`)
  - Accent / Protocol: Electric Purple (`#8b5cf6` / `#7c3aed`)
- **Typography:**
  - Primary font: `Inter` or `Outfit` via Google Fonts.
  - Monospace font for logs/rules: `Fira Code` or `JetBrains Mono`.
- **Micro-animations:**
  - Glowing pulse indicators for running captures.
  - Soft hover transitions (scale `1.02`, increase border-opacity, add drop-shadow glow).
  - Floating/scrolling packet stream logs.
  - Animated particle flow along SVG paths representing network packets.

---

## 2. Directory Structure

```
netguard/
├── core/           # shared DB models, event bus, config, setup
│   ├── __init__.py
│   ├── config.py   # loaded from env / defaults (DB paths, ML thresholds)
│   ├── db.py       # SQLite connection helpers, session context manager
│   ├── models.py   # SQLAlchemy schemas (Event, PacketLog, PhishingScan, FirewallRule, etc.)
│   └── events.py   # unified log_event() writer
├── sniffer/        # scapy live capture + anomaly scoring
│   ├── capture.py  # background capture thread
│   ├── rules.py    # signature-based checks (SYN floods, port scans, DNS tunnels)
│   ├── features.py # rolling window feature extractor per IP
│   └── anomaly.py  # IsolationForest loader and predictor
├── phishing/       # url analysis pipeline + classifier
│   ├── fetch.py    # HTTP client, redirect tracker
│   ├── cert.py     # SSL certificate metadata inspector
│   ├── domain.py   # WHOIS query & rate-limited registry lookup
│   ├── content.py  # BS4 heuristics (forms, password field checks, brand check)
│   └── analyze.py  # pipeline orchestrator + rule-based / ML scoring
├── firewall/       # rule engine + simulator
│   ├── engine.py   # iptables-like first-match-wins rule evaluation
│   ├── simulate.py # synthetic packet generator & live sniffer loop
│   └── visualize_data.py # aggregates recent decisions for Sankey rendering
├── ml/             # offline training pipeline
│   ├── models/     # directory for saved joblib pickle files
│   └── training/   # training scripts for anomaly and phishing models
├── dashboard/      # Flask, Flask-SocketIO web interface
│   ├── app.py      # main server script
│   ├── routes.py   # page controllers
│   ├── templates/  # html views (index, sniffer, phishing, firewall)
│   └── static/     # custom CSS, visualizer JS (SVG Sankey, charts)
├── data/           # datasets for ML training
├── tests/          # unit & integration tests
├── requirements.txt
└── README.md
```

---

## 3. Module Specifications

### 3.1 Shared Core (`core/`)
- **`models.py`:**
  - `Event`: ID, Timestamp, Source (`sniffer` | `phishing` | `firewall`), Severity (`info` | `warning` | `critical`), Summary, Raw Data (JSON).
  - `PacketLog`: ID, Timestamp, Src IP, Dst IP, Protocol, Length, Flags, Payload Entropy, Is Anomaly.
  - `PhishingScan`: ID, Timestamp, URL, Domain Age, Cert Validity, Form Action Check, Brand Mismatch, ML Score, Verdict.
  - `FirewallRule`: ID, Priority, Action (`allow` | `deny`), Src IP (CIDR), Dst Port, Protocol, Hit Count.
  - `FirewallDecision`: ID, Timestamp, Src IP, Dst IP, Dst Port, Protocol, Rule Matched ID, Action Taken.
- **`events.py`:**
  - `log_event(source, severity, summary, raw_data)`: Emits to database and triggers a background event loop/callback to push via WebSockets in real time.

### 3.2 Packet Sniffer (`sniffer/`)
- **`capture.py`:** Background Scapy sniffing with BPF filter. Safe state handling (pause/resume).
- **`rules.py`:**
  - Port Scan: Tracks unique destination ports per source IP in a 10s rolling window. Threat flagged if count > 15.
  - SYN Flood: Tracks ratio of TCP SYN packets to SYN-ACK responses from source IP. Threat flagged if SYN count > 30 and SYN-ACK ratio < 0.1.
  - DNS Tunneling Heuristic: Extracts domains from DNS queries. Identifies tunneling if domain length > 50 characters or character entropy is abnormally high.
  - Static Blacklist: Blocks specific malicious IPs configured in the DB/config.
- **`anomaly.py`:**
  - IsolationForest loads model from `ml/models/anomaly_model.pkl`.
  - Evaluates rolling window vectors (packets/sec, unique ports, entropy, protocol mix).

### 3.3 Phishing Page Detector (`phishing/`)
- **`analyze.py`:**
  - URL inspection triggers:
    1. Redirect Chain Length: Flagged if length > 3.
    2. Cert Check: Issuer, validity, self-signed flag.
    3. WHOIS Check: Checks domain age in days. Domain age < 30 days flags warning.
    4. Content BS4 parsing:
       - Off-domain forms: `<form>` action pointing to a different domain.
       - Password field checks: Warning if password fields exist on an insecure (HTTP) page or uncertified page.
       - Brand-keyword check: Checks if popular brand names (e.g., 'paypal', 'google', 'netflix') are present in the URL path but not in the main domain.
       - IDN Homograph check: Checks for punycode domains (`xn--`).
  - Score Calculation: Combines ML classification (LogisticRegression/RandomForest) with standard rules for explainable reasoning.

### 3.4 Interactive Firewall Simulator (`firewall/`)
- **`engine.py`:**
  - First-match-wins engine.
  - CIDR matching for IP address ranges (e.g. `192.168.1.0/24` or `10.0.0.0/8`).
  - Hit counts updated in SQLite database.
- **`simulate.py`:**
  - Synthetic Traffic: Generates random packets to demo firewall actions.
  - Live Mode: Subscribes directly to scapy's queue, forwarding real packets to the engine.

### 3.5 Dashboard & Live Views (`dashboard/`)
- **`index.html`:** The SOC Command Center. Displays scrolling unified event feed, active threat dashboard, network packet count graphs, and recent firewall events in glowing widgets.
- **`sniffer.html`:** Sniffer control deck. Real-time graphs showing packet protocol distribution (pie chart), packets/sec (line chart), and detailed packet attribute tables.
- **`phishing.html`:** Clean input field to scan a URL, displaying an interactive report with certificate information, WHOIS logs, HTML parsing highlights, and the threat level gauge.
- **`firewall.html`:** Interactive rules editor. Add, delete, and reorder rules. The page features a gorgeous SVG-based Sankey/Flow Visualizer. Traffic flows from "Source IP" -> "Rules Matched" -> "Action (Allow/Deny)". The lines are animated with particle dots showing live traffic passing.

---

## 4. Immediate Development Workflow & Commits
Every change must be committed and pushed immediately.
Milestones:
1. Core Database & Model Setup
2. Firewall Engine & Simulation
3. Scapy Sniffer & Rule-Based Detection
4. Connecting Sniffer to Firewall
5. Phishing Page Analyzer Pipeline
6. ML Offline Training Scripts
7. Flask Web App + WebSockets HUD Interface
