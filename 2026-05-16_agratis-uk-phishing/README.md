# threat-intel — a-gratis.uk Phishing Network

Detection rules and IOCs for the **a-gratis.uk phishing network** targeting government social benefit programs in Indonesia and Malaysia.

Full technical report: https://sudo-rwx4m.my.id/projects/TI-Report_Phishing-Network_a-gratis-uk

---

## Overview

| Attribute | Detail |
|:---|:---|
| **Threat Type** | Phishing — Government Impersonation |
| **Target** | Indonesia 🇮🇩 (PKH Kemensos), Malaysia 🇲🇾 (PPR, Job Scam) |
| **Objective** | Telegram Account Takeover |
| **Infrastructure** | Cloudflare CDN + Next.js |
| **Active Since** | 2026-03-20 (via CT log) |
| **Confirmed Active** | 2026-05-16 (all 5 subdomains HTTP 200) |
| **TLP** | WHITE |

---

## Repository Structure

```
.
├── ioc/
│   └── ioc_aGratisUK_network.txt       # Domains, URLs, IPs, cert IDs, content signatures
├── yara/
│   └── phishing_aGratisUK_network.yar  # 6 YARA rules (per-campaign + broad)
├── sigma/
│   └── phishing_aGratisUK_network.yml  # 4 Sigma rules (proxy, DNS, network)
└── snort/
    └── phishing_aGratisUK_network.rules # 7 Snort/Suricata rules
```

---

## Active Subdomains

All confirmed HTTP 200 on 2026-05-16:

| Subdomain | Campaign | Target |
|:---|:---|:---|
| `bansos-terkini.a-gratis.uk` | PKH Kemensos lure — Rp 1.500.000 | Indonesia |
| `bantuan-ppr-terkini.a-gratis.uk` | PPR housing program lure | Malaysia |
| `daftar-segera.a-gratis.uk` | Generic registration form | Indonesia |
| `daftar-segeraa.a-gratis.uk` | Backup domain (identical content) | Indonesia |
| `jawatan-kosong-terkini.a-gratis.uk` | Job scam — fake salary listings | Malaysia |

---

## Detection Rules

### YARA (`yara/`)

| Rule | Detects | Confidence |
|:---|:---|:---|
| `Phishing_aGratisUK_Domain` | Any page containing `a-gratis.uk` | HIGH |
| `Phishing_aGratisUK_Indonesia_PKH` | bansos-terkini campaign | HIGH |
| `Phishing_aGratisUK_Malaysia_PPR` | bantuan-ppr-terkini campaign | HIGH |
| `Phishing_aGratisUK_Malaysia_JobScam` | jawatan-kosong campaign | HIGH |
| `Phishing_aGratisUK_Indonesia_Generic` | daftar-segera campaign | HIGH |
| `Phishing_aGratisUK_Network_Broad` | Any campaign variant | MEDIUM |

All strings verified against live source HTML captured on 2026-05-16.

**Usage:**
```bash
yara -r yara/phishing_aGratisUK_network.yar /path/to/scan/
```

### Sigma (`sigma/`)

| Rule | Log Source | Confidence |
|:---|:---|:---|
| `Phishing a-gratis.uk — Domain Access via Proxy` | Web proxy | HIGH |
| `Phishing a-gratis.uk — Known Active Subdomains` | Web proxy | HIGH |
| `Phishing a-gratis.uk — DNS Resolution` | DNS | HIGH |
| `Phishing a-gratis.uk — Cloudflare IP + Host Header` | Network/Zeek | MEDIUM |

**Convert to your SIEM:**
```bash
# Elastic
sigma convert -t lucene sigma/phishing_aGratisUK_network.yml

# Splunk
sigma convert -t splunk sigma/phishing_aGratisUK_network.yml

# QRadar
sigma convert -t qradar sigma/phishing_aGratisUK_network.yml
```

### Snort / Suricata (`snort/`)

7 rules covering HTTP host header matching per subdomain + DNS query detection.

**Usage:**
```bash
# Suricata
suricata -c /etc/suricata/suricata.yaml -S snort/phishing_aGratisUK_network.rules

# Snort 3
snort -c /etc/snort/snort.lua --plugin-path snort/phishing_aGratisUK_network.rules
```

> **Important:** SIDs `9000001–9000007` are used. Check for conflicts with your existing ruleset before deployment.

---

## IOC Quick Reference

**Domains (block these):**
```
a-gratis.uk
bansos-terkini.a-gratis.uk
bantuan-ppr-terkini.a-gratis.uk
daftar-segera.a-gratis.uk
daftar-segeraa.a-gratis.uk
jawatan-kosong-terkini.a-gratis.uk
```

**Pi-hole / hosts file:**
```
0.0.0.0 a-gratis.uk
0.0.0.0 bansos-terkini.a-gratis.uk
0.0.0.0 bantuan-ppr-terkini.a-gratis.uk
0.0.0.0 daftar-segera.a-gratis.uk
0.0.0.0 daftar-segeraa.a-gratis.uk
0.0.0.0 jawatan-kosong-terkini.a-gratis.uk
```

> **Note on IPs:** `104.21.43.223` and `172.67.186.183` are Cloudflare anycast proxies. Do **not** block these IPs — they serve thousands of unrelated legitimate sites. Use domain-based blocking only.

---

## Methodology

All IOCs and detection strings were verified through:

- DNS resolution via Google DoH
- Certificate Transparency log enumeration
- HTTP response header capture
- Source HTML capture and string extraction

No active exploitation or form submission was performed during investigation.

---

## License

[MIT](LICENSE) — free to use, modify, and distribute with attribution.

---

**Author:** [rwx4m](https://sudo-rwx4m.my.id) | **Date:** 2026-05-16 | **TLP:** WHITE
