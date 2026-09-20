# sRX87 — SSL/TLS RECONNAISSANCE AND EXPLOITATION FRAMEWORK 


<div align="center">

<img src="https://img.shields.io/badge/sRX87-ULTIMATE-blueviolet.svg?style=for-the-badge&logo=github" alt="sRX87">
<img src="https://img.shields.io/badge/VERSION-1.0.0-blue.svg?style=for-the-badge" alt="Version">
<img src="https://img.shields.io/badge/STATUS-STABLE-brightgreen.svg?style=for-the-badge" alt="Status">
<img src="https://img.shields.io/badge/LICENSE-MIT-orange.svg?style=for-the-badge" alt="License">

<br>

<img src="https://img.shields.io/badge/PYTHON-3.8%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/LINUX-SUPPORTED-FCC624.svg?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
<img src="https://img.shields.io/badge/WINDOWS-SUPPORTED-0078D6.svg?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
<img src="https://img.shields.io/badge/MACOS-SUPPORTED-000000.svg?style=for-the-badge&logo=apple&logoColor=white" alt="macOS">

<br>

<img src="https://img.shields.io/badge/ROOT-OPTIONAL-success.svg?style=for-the-badge" alt="Root">
<img src="https://img.shields.io/badge/NON--ROOT-SUPPORTED-success.svg?style=for-the-badge" alt="Non-Root">
<img src="https://img.shields.io/badge/CLI-TOOL-6E40C9.svg?style=for-the-badge" alt="CLI">
<img src="https://img.shields.io/badge/SECURITY-RESEARCH-red.svg?style=for-the-badge" alt="Security Research">

<br><br>

<strong>sRX87</strong><br>
<sub>Advanced Security Research &amp; Testing Framework</sub>

</div>

sRX87 is a single-file, dependency-resilient SSL/TLS reconnaissance and exploitation framework authored by SYLHETYHACKVENGER (THE-ERROR808). It implements a 12-stage sequential kill-chain covering transport recon, X.509 parsing, protocol/cipher enumeration, cryptographic oracles, HTTP-layer attacks, TLS bypass, HTTP bypass, auth/ACL attacks, SSRF/cache/rate-limit abuse, cloud metadata harvesting, CVE correlation, and 20-format reporting. Unlike typical "scanner wrappers," sRX87 speaks raw TLS at the byte level — it hand-crafts ClientHellos, parses ServerHello/ServerKeyExchange/Certificate messages with its own DER reader, and executes real oracles (ROBOT, Bleichenbacher, Heartbleed, Lucky13 with Welch t-test, Fermat/batch-GCD factorization, Wiener). It runs 3,000+ KB-evidence-backed probes, writes STIX 2.1, MISP, SARIF, Nessus, Burp, ZAP, and DefectDojo exports, and renders a live alt-screen TUI with scrollback. This is a professional-grade offensive/defensive instrument — not a toy.

---

Full Capability Breakdown

Stage 01 — Transport & Recon (20 tests)

· TCP connect + RTT, service banner grab, UDP reachability
· DNS A/AAAA/CNAME/HTTPS (SVCB) resolution via dnspython with socket fallback
· SSLv3 → TLS 1.3 version probes, ServerHello decode, extension enumeration
· SNI probe + no-SNI default-vhost detection
· 1-byte TLS record fragmentation, RTT baseline (median/min/max/stdev)
· TCP/IP fingerprint (TTL, window, MSS, hop estimation)

Stage 02 — Certificate Chain Analysis (10 tests)

· Multi-version chain capture (TLS 1.3 → 1.0 fallback)
· Full X.509 DER parser (subject, issuer, SAN, key usage, EKU, basic constraints, AIA, CRL, SCT, must-staple)
· RSA/EC/Ed25519 public key extraction, modulus/exponent inspection
· Signature algorithm grading (MD5/SHA1 = CRITICAL)
· Wildcard depth analysis, expiry math, CN/SAN consistency, chain order

Stage 03 — Protocol & Cipher Enumeration (20 tests)

· Real ServerHello pinning per cipher suite (rounds loop)
· TLS 1.0/1.1/1.2/1.3 + SSLv3 enumeration
· Key-size histogram, KX breakdown, AEAD vs CBC ratio
· NULL/EXPORT/anon/RC4/3DES detection
· Server cipher preference (order reversal)
· EC curve enumeration, preferred curve
· Signature algorithm enumeration, SHA-1/MD5 detection
· ALPN enumeration + h2 preference test
· FALLBACK_SCSV, renegotiation SCSV, TLS compression, session resumption, EMS

Stage 04 — Cryptographic Vulnerability Probes (19 tests)

· Heartbleed — extension check + 32-request 16KB memory dump with credential marker search
· ROBOT — 32-iteration PKCS#1v1.5 padding oracle
· Lucky13 — 40-sample CBC vs GCM Welch t-test
· Bleichenbacher CCA — good/bad padding alert differentiation
· POODLE — SSLv3 + CBC precondition
· DROWN — SSLv2 ClientHello
· FREAK/Logjam — export cipher acceptance
· RC4, CRIME, BEAST, BREACH, TIME
· DH weak prime (primality + smoothness), DH small subgroup
· ECDH invalid curve, ECDSA nonce reuse (r-value collision)
· Wiener attack, Fermat + batch-GCD on chain moduli

Stage 05 — HTTP Layer Attacks (17 tests)

· HTTP/1.0, HTTP/0.9 bare GET
· HTTP/2 ALPN, SETTINGS exchange, pseudo-headers
· Rapid Reset (CVE-2023-44487), CONTINUATION flood (CVE-2024-27316)
· Request smuggling: CL.TE, TE.CL, TE.TE (4 variants), CL.0, H2.CL, H2.TE
· Pipelining, Expect: 100-continue, chunked trailers, header oddities

Stage 06 — TLS Bypass (15 tests)

· SNI variants: uppercase, trailing-dot, null-byte, leading-dot, omitted
· GREASE injection (RFC 8701)
· Version downgrade, weak cipher groups in isolation
· Duplicate extensions, malformed extension lengths
· Past/future ClientHello randoms, RSA-only cipher negotiation
· ECH GREASE, JA3 fingerprint + browser profile matching

Stage 07 — HTTP Bypass (16 tests)

· Header case, duplicate Host/XFF, whitespace, obs-fold, null bytes, UTF-8
· Malformed chunks, path double/triple slash, backslash, trailing dots
· Semicolon params, URL encoding, overlong UTF-8
· Method override (X-HTTP-Method-Override, X-Method-Override), method case, _method body
· Full forwarded header chain (XFF, X-Real-IP, Forwarded, X-Original-URL, X-Rewrite-URL)

Stage 08 — Auth & ACL Bypass (13 tests)

· JWT alg:none, kid traversal, kid SQLi, jku SSRF, expired/far-future exp
· OAuth redirect_uri reflection (path + payload matrix)
· X-Original-URL / X-Rewrite-URL path override
· Forced browse (40 sensitive paths)
· Sequential IDOR (9 patterns × 5 IDs)
· Auth bypass headers (9 variants)
· Role injection (cookies + headers)
· Dangerous HTTP methods (OPTIONS, TRACE, PUT, DELETE, PROPFIND, WEBDAV)
· Double-encoded path traversal (9 payloads)

Stage 09 — SSRF / Cache / Rate-Limit (13 tests)

· SSRF batteries across 36 parameter names
· Decimal/octal/hex/short IP, IPv6 loopback
· Cloud metadata: AWS, GCP, Alibaba
· Parser confusion (@ # \ ? null)
· Gopher/dict/ldap/tftp schemes
· Cache poisoning: X-Forwarded-Host, unkeyed cookie, Host reflection
· Rate-limit bypass: XFF rotation, path case rotation, 20-thread concurrent burst

Stage 10 — Cloud / Supply Chain (10 tests)

· AWS IMDSv1 (5 paths) + IMDSv2 (real token PUT + authenticated fetch)
· GCP metadata, Alibaba Cloud metadata
· Kubernetes SA token + API probe
· Docker socket + TCP 2375/2376
· Container capability enumeration
· IPv6 reachability, AXFR zone transfer, DNSSEC presence

Stage 11 — CVE Correlation & Chains (20 tests)

· 15 real CVEs: Heartbleed, DROWN, POODLE, Logjam, FREAK, ROCA, AES-NI CBC, Ticketbleed, Java psychic sigs, Apache XFF, Rapid Reset, CONTINUATION, 0-byte padding, Raccoon, Manger
· Heap search for 48B session secrets / JWTs / cookies in leaked memory
· Reverse-TLS material prep (mimic CN/SAN/serial)
· Attack timeline reconstruction, baseline diff

Stage 12 — Reporting (20 formats)

JSON, CSV, HTML, STIX 2.1, MISP, Neo4j Cypher, ATT&CK map, CVSS 4.0, interactive dashboard, timeline, PDF, SARIF, DefectDojo, GitHub issues, Jira CSV, Nessus XML, Burp XML, ZAP XML, plain-text summary, exec verdict.

---

 # Advantages of sRX87

Below is a disciplined, professional breakdown of where sRX87 delivers genuine operational value in cybersecurity — framed by use case, not feature list.

---

1. Authorized Penetration Testing & Red Team

· Full kill-chain coverage in one binary — transport → cert → crypto → HTTP → auth → SSRF → cloud → CVE → report. No tool-chaining, no context loss between phases.
· Byte-level TLS control gives red teams protocol-level bypasses (SNI null-byte, duplicate extensions, GREASE, record fragmentation) that commercial scanners cannot reproduce.
· Real oracles, not heuristics — ROBOT, Bleichenbacher, Lucky13 (with Welch t-test), Heartbleed memory dump. Findings are reproducible evidence, not confidence scores.
· Attack chain planning — Stage 11 auto-composes multi-step exploit plans from detected preconditions, ready to hand to a red-team operator.

2. Defensive Security / Blue Team Validation

· Baseline diffing (srx87_baseline.json) — detect regressions after config changes, patches, or infrastructure drift.
· CVE correlation against 15 tracked vulnerabilities — instantly answers "is our stack exposed to Heartbleed / POODLE / Rapid Reset / CONTINUATION flood?"
· Posture verdict — single CRITICAL/HIGH/MEDIUM/LOW score for executive reporting.
· Continuous validation — run on a schedule against staging to prove hardening holds.

3. Compliance & Audit Evidence

· 20 export formats mapped to industry workflows: SARIF (CI/CD), STIX 2.1 (threat intel), MISP (sharing), Nessus/Burp/ZAP (vuln management), DefectDojo/Jira/GitHub Issues (ticketing), CVSS 4.0 (scoring).
· Immutable evidence ledger — every finding carries a KB key, timestamp, and stage provenance. Audit-grade traceability.
· MITRE ATT&CK mapped — 39 technique patterns tagged automatically, satisfying TTP-coverage requirements in many frameworks.

4. DevSecOps / CI-CD Integration

· Single-file, zero mandatory deps — drop into any pipeline (python3 srx87.py tls://staging:443).
· SARIF output plugs directly into GitHub Code Scanning, GitLab SAST, Azure DevOps.
· Exit-code friendly — posture verdict enables gate failures on CRITICAL/HIGH.
· Deterministic stages — --stage N runs a single stage for fast PR checks (e.g. cert expiry only).

5. Cloud & Container Security

· AWS IMDSv1 + IMDSv2 (real token PUT), GCP, Alibaba metadata probing — the #1 cloud credential-theft vector.
· Kubernetes SA token + API, Docker socket, container capability enumeration — direct container-escape reconnaissance.
· SSRF to cloud metadata chain — proves whether a URL parameter can pivot to cloud credentials.

6. Threat Intelligence & Research

· JA3 fingerprinting + browser profile matching — identify malware families, C2 frameworks, or policy-evading clients.
· Heap search in Heartbleed leaks for 48-byte session secrets, JWTs, cookies — feeds intel pipelines.
· STIX/MISP export — share findings with ISACs, SOCs, and threat-sharing platforms in native format.

7. Education & Skills Development

· Transparent implementation — every test is readable Python; students see how the attack works, not just that it worked.
· 12-stage structure mirrors the real pentest methodology (recon → analysis → exploitation → reporting).
· Safe defaults — the Heartbleed dump is opt-in (heartbleed.dump), rate-limit tests are bounded, no destructive payloads.

8. Incident Response & Forensics

· Live posture snapshot during an active incident — is the attacker's target actually vulnerable?
· Timeline reconstruction — Stage 11 rebuilds the attack sequence from KB events.
· Reverse-TLS material prep — mimic CN/SAN/serial for counter-surveillance or honeypot deployment.

9. Risk Prioritization

· CVSS 4.0 scoring per finding — not a flat list, but a ranked exploit surface.
· Severity classification (CRITICAL / HIGH / MEDIUM / LOW / INFO) tied to real-world exploitability, not vendor CVSS alone.
· Attack chain viability — tells leadership "this is exploitable end-to-end" vs "this is a theoretical weakness."

10. Operational Efficiency

· One tool replaces 6–10 (testssl.sh, sslyze, TLS-Attacker, Burp TLS plugins, Nuclei templates, cloud-enum, SSRF tools, report generators).
· Parallel stages with ThreadPoolExecutor — SSRF batteries and rate-limit tests run concurrently.
· Graceful degradation — runs even in minimal environments (no pycryptodome, requests, dnspython, colorama).
· Single artifact to audit — no supply-chain risk from dozens of pip packages.

---
```
Where It Excels vs. Alternatives

Capability sRX87      vs      testssl.sh sslyze Burp Nuclei
Byte-level TLS crafting ✅           partial ❌ ❌ ❌
Real crypto oracles (ROBOT, Lucky13) ✅   ❌ ❌ ❌ ❌
Heartbleed memory dump ✅                 ❌ ❌ ❌ ❌
HTTP smuggling (6 variants) ✅         ❌ ❌ partial ✅
Cloud metadata (AWS/GCP/Alibaba) ✅.        ❌ ❌ ❌ ✅
JWT + OAuth + ACL bypass ✅            ❌ ❌ partial ✅
20 report formats ✅                 partial partial ✅ partial
Single file, no install ✅                ✅ ❌ ❌ ❌
MITRE ATT&CK mapping ✅                     ❌ ❌ ❌ ✅
```
---

Bottom Line for Security Teams

sRX87 is a force multiplier for authorized offensive work and a continuous assurance engine for defensive teams. Its proper advantages are: protocol-depth no other single tool matches, real evidence instead of guesses, enterprise-ready reporting, and deployment simplicity. It belongs in every pentester's toolkit and every blue team's validation pipeline — used strictly within scope and with written authorization.
---



sRX87 is a research-grade offensive TLS framework with detection depth rivaling testssl.sh, sslyze, and TLS-Attacker — combined with auth/SSRF/cloud capabilities normally found in Burp Suite + Nuclei + cloud-enum tools. It is not for unauthorized use; it is a professional pentest/red-team instrument suitable for authorized engagements, CTFs, bug bounties (scope-permitting), and internal security validation. Weaknesses: no test-timeout enforcement (the timeout field on TestSpec is metadata-only), no rate-limit courtesy throttling, and the KB is in-memory (no resume). Strengths far outweigh these — this is a top-tier tool.

Author: SYLHETYHACKVENGER (THE-ERROR808)
