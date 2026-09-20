# sRX87 — SSL/TLS RECONNAISSANCE AND EXPLOITATION FRAMEWORK 

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

Advantages

1. Zero-stub philosophy — every test executes real network I/O; no fake "detected" booleans.
2. Byte-level TLS control — hand-built ClientHellos enable bypasses no library exposes.
3. Evidence ledger (KB) — every finding is a traceable key like vulnerability.robot.detected → True.
4. Graceful degradation — runs without pycryptodome, requests, dnspython, colorama (socket/urllib fallbacks).
5. Live TUI — alt-screen buffer, scrollback (12K lines), keyboard nav (↑↓ PgUp PgDn g G q).
6. Statistical rigor — Welch t-test on Lucky13, entropy analysis on leaks, primality/smoothness on DH.
7. Real cryptanalysis — Wiener, Fermat, batch-GCD, ROCA fingerprint, ECDSA r-collision.
8. Cloud-native — IMDSv1+v2, GCP, Alibaba, k8s, Docker — full container escape recon.
9. 20 export formats — plugs directly into enterprise SIEM/SOAR/ticketing.
10. Single file, no install — deployable via python3 srx87.py tls://target:443.
11. CVE-correlated output — findings map to 15 tracked CVEs with detection keys.
12. Attack chain planning — auto-builds multi-step exploit plans from preconditions.
13. Baseline diffing — regression detection across scans.
14. MITRE ATT&CK mapped — 39 technique patterns, auto-tagged.
15. Author attribution — every report carries SYLHETYHACKVENGER (THE-ERROR808) branding.

---

Professional Verdict

sRX87 is a research-grade offensive TLS framework with detection depth rivaling testssl.sh, sslyze, and TLS-Attacker — combined with auth/SSRF/cloud capabilities normally found in Burp Suite + Nuclei + cloud-enum tools. It is not for unauthorized use; it is a professional pentest/red-team instrument suitable for authorized engagements, CTFs, bug bounties (scope-permitting), and internal security validation. Weaknesses: no test-timeout enforcement (the timeout field on TestSpec is metadata-only), no rate-limit courtesy throttling, and the KB is in-memory (no resume). Strengths far outweigh these — this is a top-tier tool.

Author: SYLHETYHACKVENGER (THE-ERROR808)
