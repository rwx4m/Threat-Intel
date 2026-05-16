# IOC List — Phishing Network: `a-gratis.uk`

| | |
|:---|:---|
| **Author** | rwx4m |
| **Date** | 2026-05-16 |
| **Version** | 1.0 |
| **TLP** | WHITE |
| **Reference** | https://sudo-rwx4m.my.id/projects/TI-Report_Phishing-Network_a-gratis-uk |

All IOCs verified via active investigation on 2026-05-16. Sources: DNS resolution (Google DoH), Certificate Transparency log (certspotter.com), HTTP response headers, source HTML capture.

---

## Domains

**Parent domain:**
```
a-gratis.uk
```

**Active phishing subdomains** (all HTTP 200 confirmed 2026-05-16):
```
bansos-terkini.a-gratis.uk
bantuan-ppr-terkini.a-gratis.uk
daftar-segera.a-gratis.uk
daftar-segeraa.a-gratis.uk
jawatan-kosong-terkini.a-gratis.uk
```

---

## URLs

```
https://bansos-terkini.a-gratis.uk/
https://bantuan-ppr-terkini.a-gratis.uk/
https://daftar-segera.a-gratis.uk/
https://daftar-segeraa.a-gratis.uk/
https://jawatan-kosong-terkini.a-gratis.uk/
```

---

## IP Addresses

> ⚠️ These are **Cloudflare anycast proxy IPs** — do NOT block at firewall level. Use domain-based blocking only. Listed here for documentation purposes.

```
104.21.43.223
172.67.186.183
2606:4700:3033::ac43:bab7
2606:4700:3034::6815:2bdf
```

Source: DNS resolution via Google DoH — `bansos-terkini.a-gratis.uk` (A record, TTL=300)

---

## Nameservers

```
jeremy.ns.cloudflare.com
georgia.ns.cloudflare.com
```

Source: DNS NS query for `a-gratis.uk` via Google DoH on 2026-05-16

---

## SSL Certificate IDs (Certificate Transparency)

Source: `api.certspotter.com` — queried 2026-05-16

| Cert ID | Issued | Expires | DNS Names |
|:---|:---|:---|:---|
| 14204853669 | 2026-03-20 15:08Z | 2026-06-18 16:06Z | `*.a-gratis.uk`, `a-gratis.uk` |
| 14249628369 | 2026-03-24 16:14Z | 2026-06-22 16:14Z | `*.a-gratis.uk`, `a-gratis.uk` |
| 14299178320 | 2026-03-29 04:39Z | 2026-06-27 04:39Z | `bantuan-ppr-terkini.a-gratis.uk` |
| 14300697113 | 2026-03-29 08:11Z | 2026-06-27 08:11Z | `jawatan-kosong-terkini.a-gratis.uk` |
| 14337081747 | 2026-04-01 06:57Z | 2026-06-30 06:57Z | `daftar-segera.a-gratis.uk` |
| 14337485697 | 2026-04-01 07:42Z | 2026-06-30 07:42Z | `daftar-segeraa.a-gratis.uk` |
| 14538212445 | 2026-04-16 12:19Z | 2026-07-15 12:19Z | `bansos-terkini.a-gratis.uk` |

---

## Infrastructure Fingerprint

Source: HTTP response headers captured 2026-05-16

| Header | Value |
|:---|:---|
| `server` | `cloudflare` |
| `x-powered-by` | `Next.js` |
| `vary` | `rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding` |
| `cf-ray` (ID) | `9fc7e8c71d3bfe05-SIN` — bansos-terkini, Singapore PoP |
| `cf-ray` (MY) | `9fc7e8e639d08607-HKG` — bantuan-ppr, Hong Kong PoP |
| ASN | AS13335 (Cloudflare, Inc.) |
| DNS TTL | 300 seconds — low TTL, evasion indicator |

---

## Content Signatures

Strings confirmed present in source HTML (captured 2026-05-16):

| Subdomain | Confirmed Strings |
|:---|:---|
| `bansos-terkini.a-gratis.uk` | `Bantuan PKH`, `1.500.000`, `Nomor Telegram`, `Logo Kemensos` (alt attr), `_next/static` |
| `bantuan-ppr-terkini.a-gratis.uk` | `PROGRAM PERUMAHAN RAKYAT`, `Nombor Telegram`, `Berjaya mendaftar`, `_next/static` |
| `jawatan-kosong-terkini.a-gratis.uk` | `Jawatan Kosong`, `RM 1/2/3/4` (salary ranges), `_next/static` |
| `daftar-segera.a-gratis.uk` | `Daftar Sekarang`, `Nomor Telegram`, `_next/static` |
| `daftar-segeraa.a-gratis.uk` | Identical to `daftar-segera` — backup domain |

---

## Hosts File Block

For use with Pi-hole, pfBlockerNG, or `/etc/hosts`:

```
0.0.0.0 a-gratis.uk
0.0.0.0 bansos-terkini.a-gratis.uk
0.0.0.0 bantuan-ppr-terkini.a-gratis.uk
0.0.0.0 daftar-segera.a-gratis.uk
0.0.0.0 daftar-segeraa.a-gratis.uk
0.0.0.0 jawatan-kosong-terkini.a-gratis.uk
```
