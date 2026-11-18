# ELITEWOLF rules for Snort 3 and Suricata 7

Fork-maintained port of the ELITEWOLF signatures. This is not an NSA release.
Upstream stopped updating the signatures in 2023 and asked the community to
maintain them; this directory is that.

| File | Engine | Rules |
|---|---|---|
| `suricata/elitewolf.rules` | Suricata 7 (tested on 7.0.17) | 57 |
| `snort3/elitewolf.rules` | Snort 3 (tested on 3.10.0.0) | 51 |

The original Snort 2 text files in the repository root are kept as they were,
apart from unique SIDs (branch `fix/unique-sids`).

## Using them

Suricata: add the file to `rule-files` in `suricata.yaml`, or
`suricata -c suricata.yaml -S rules/suricata/elitewolf.rules ...`.

Snort 3: `snort -c snort.lua -R rules/snort3/elitewolf.rules ...`, or add it to
`ips.include`. The HTTP and certificate rules use service headers
(`alert http`, `alert ssl`), so the stock `wizard` and `http_inspect`/`ssl`
inspectors from `snort.lua` must be enabled.

All rules use `any` addresses. Restrict them to your OT segments (`$HOME_NET`,
a device list) before deploying; several strings (`Level 1`, `USER ACC`) are
short and only make sense on traffic to SEL devices.

## What changed from the Snort 2 files

- **Unique SIDs.** Upstream gave every rule `sid:1`. Suricata loads 1 of the 52
  and fails the rest; Snort 3 keeps one and drops 51 as duplicates.
- **HTTP rules are protocol-detected, not port-bound.** The Rockwell, SEL and
  Siemens URL-path rules matched raw bytes from source port 80 or 443. They now
  match the HTTP response body (`file.data` / `file_data`) on any port, which
  also covers gzip-compressed pages and web servers on non-standard ports. The
  match stays on the server side: upstream confirmed the rules are meant to see
  the device's own pages, not client requests.
- **No URL matching on port 443.** A path such as `/home.sel` is inside the TLS
  record and cannot match unless the traffic is decrypted. Those rules now fire
  on plain HTTP (or decrypted HTTPS); over TLS, rely on the certificate rules.
- **Certificate rules.** Upstream had three rules per certificate: the bare
  string, `commonName=<string>` and `issuer_CN: <string>`. The last two are
  text from a certificate log formatter and never appear in the DER bytes on
  the wire, so they could not fire. Suricata now uses one `tls.cert_subject`
  and one `tls.cert_issuer` rule per certificate. Snort 3 has no certificate
  field buffer, so it uses one `alert ssl` rule on the raw certificate bytes.
  Both only see certificates in TLS 1.2 and earlier; TLS 1.3 encrypts them.
- **`flow`, `classtype`, `reference`, `metadata`** on every rule. Each PCRE has
  a literal `content` in front of it so the fast-pattern matcher can prefilter.
  `STOR SET_[0-9A-Z]{1,4}.TXT` now escapes the dot.
- **SSH (Suricata).** The dropbear banner rule uses `ssh.software`. Snort 3
  keeps the raw banner match. Both keep upstream's port 1024.

## Community rules folded in

- **PR #3, Tridium Niagara certificates** (Ken Buckler, `kenbuckler`). Kept the
  `NiagaraAX`, `Niagara4` and `NiagaraN4` names as subject/issuer rules. The
  bare `Niagara` rule is dropped: it is a substring of the other three and
  fires on any certificate containing the word.
- **PR #7, Siemens LOGO! web login brute force** (Erwan Cordier,
  `biero-el-corridor`). The PR used `threshold:type limit, count 5, seconds 15`,
  which alerts on the first 5 attempts and then goes quiet. The port uses
  `detection_filter:track by_src, count 5, seconds 15`, which stays quiet until
  a source makes more than 5 attempts in 15 seconds. The match is now on the
  parsed request (`POST`, URI starting `/AJAX`, body starting `UAMCHAL:`).

## SID map

| SID | Upstream rule | Suricata | Snort 3 |
|---|---|---|---|
| 1000001-1000014 | Rockwell URL paths (port 80) | `file.data`, rev 2 | `file_data`, rev 2 |
| 1000015, 1000017 | SEL-3530 `/home.sel`, `/default.sel` (port 443) | `file.data`, rev 2 | `file_data`, rev 2 |
| 1000016 | SEL-3530 `/errors/err401.sel?username=` (port 443) | raw server-side HTTP stream (header or body), rev 2 | `http_header` only (Snort 3 rules on `alert http` do not see the raw stream), rev 2 |
| 1000018 | SEL-3530 dropbear SSH banner (port 1024) | `ssh.software`, rev 2 | raw banner, rev 2 |
| 1000019 | SEL-3530 `SEL-3530 RTAC` (port 5432) | rev 2 | rev 2 |
| 1000020 | SEL-3620 certificate, bare string | `tls.cert_subject` | raw certificate |
| 1000021 | SEL-3620 `commonname=` | retired | retired |
| 1000022 | SEL-3620 `issuer_CN:` | `tls.cert_issuer` | not present |
| 1000023-1000024 | SEL-2488 URL paths (port 443) | `file.data`, rev 2 | `file_data`, rev 2 |
| 1000025 | SEL-2488 `commonName=` | `tls.cert_subject` | raw certificate |
| 1000026 | SEL-2488 `issuer_CN:` | `tls.cert_issuer` | not present |
| 1000027-1000031 | SEL Telnet (port 23) | rev 2 | rev 2 |
| 1000032-1000047 | SEL FTP (port 21) | rev 2 | rev 2 |
| 1000048-1000049 | S7-1200 URL paths (port 80) | `file.data`, rev 2 | `file_data`, rev 2 |
| 1000050 | S7-1200 certificate, bare string | `tls.cert_subject` | raw certificate |
| 1000051 | S7-1200 `commonName=` | retired | retired |
| 1000052 | S7-1200 `issuer_CN:` | `tls.cert_issuer` | not present |
| 1000101-1000106 | PR #3 Niagara (subject, issuer per name) | `tls.cert_subject` / `tls.cert_issuer` | subject SIDs only, raw certificate |
| 1000107 | PR #7 LOGO! brute force | `detection_filter` | `detection_filter` |

## Known overlaps

These are inherent in the upstream strings and are asserted by the tests:

- Rockwell `pageReq=tcp`, `udp` and `ip` are prefixes of `tcpconn`,
  `udptable` and `iproute`, so the longer pages also raise the shorter rule.
- `STOR SET_DNP1.TXT` and `RETR SET_DNP1.TXT` also raise the generic
  `STOR SET_` / `RETR SET_` rules.
- A Telnet banner containing `SEL-2032 COMMUNICATIONS PROCESSOR-S/N` also
  raises the generic `SEL-nnnn` Telnet rule.

## Tests

`tests/` builds a synthetic pcap corpus with scapy (no vendor traffic) and
replays it through both engines in containers. Every rule has at least one
positive pcap, and every pcap must raise exactly its expected set of SIDs, so
negatives fail on any alert. See `tests/cases.py` for the cases.

```
pip install -r tests/requirements.txt
sh tests/run.sh               # both engines; DOCKER="sudo docker" if needed
sh tests/run.sh suricata
```

CI (`.github/workflows/rules.yml`) runs the same script plus a load check of the
root Snort 2 text files on every push.
