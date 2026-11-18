# LANE 5 report: ELITEWOLF

## 1. Upstream contribution rules (CONTRIBUTING.md)

- CC0 1.0 waiver: by opening a PR a non-government contributor releases the change under CC0. No CLA and no DCO.
- No CI, tests, issue templates or PR templates in the repo.
- In practice the project is closed to rule changes. On PRs #1, #3 and #5 (Oct 2023), `iadgovuser52` wrote: "we're not
  updating the signatures/analytics at this time ... We strongly encourage the community to create or update the
  signatures/analytics for their own purposes and to share those updates too."
- No PR has ever been merged. Last commit was 2023-10-12 (a README edit).

## 2. Branches

| Branch | Base | Bound for | Commit |
|---|---|---|---|
| `fix/unique-sids` | upstream/master | issue only (PR not expected to land) | `ff5d5da` Assign unique SIDs so the rule files load |
| `lane/snort3-suricata7` | `fix/unique-sids` | fork only | `d35deb3` rule sets, tests, CI; plus this report |

### A: `fix/unique-sids`
One squashed commit. The 52 rules change from `sid:1` to `sid:1000001`-`sid:1000052` (local-rules range, file order:
Rockwell 1000001-014, SEL 1000015-047, Siemens 1000048-052), keeping `rev:1`. Nothing else changes: same headers,
contents, messages, CRLF line endings and missing final newline. Diff: 3 files, 52 insertions, 52 deletions.

### B: `lane/snort3-suricata7`
- `rules/suricata/elitewolf.rules` (57 rules) and `rules/snort3/elitewolf.rules` (51 rules). These are separate files
  because the syntax diverges (sticky-buffer names, `content` modifiers, no certificate buffers in Snort 3). The root
  `.txt` files are left as they are on A.
  - **HTTP rules** (Rockwell, SEL, S7-1200 paths) use `alert http` + `flow:established,to_client` + `file.data` /
    `file_data`, so they match on any port, including gzip bodies. The match stays server-side because the maintainers
    said on #5 that the direction is intentional.
  - **443/TLS.** The URL-path rules can't see inside TLS, so they now run on HTTP only. The certificate triples (bare
    string, `commonName=`, `issuer_CN:`) become one `tls.cert_subject` rule and one `tls.cert_issuer` rule each on
    Suricata. On Snort 3 they become one `alert ssl` raw-certificate rule, because Snort 3 has no X.509 field buffer.
    SIDs 1000021 and 1000051 are retired. The `commonName=` / `issuer_CN:` strings are log-formatter text and never
    appear in DER. I checked that against the test certs: the subject-in-O case fires and nothing matches the
    formatter text. SNI was not used: these devices are normally reached by IP, so there is no vendor SNI to match.
  - SSH uses `ssh.software` (Suricata). Every rule has a `flow`. Each PCRE has a literal `content` prefilter. The
    `STOR SET_` PCRE dot is escaped. Every rule has a `classtype` (misc-activity, protocol-command-decode,
    default-login-attempt for the SEL default credentials, attempted-user for brute force), a `reference` and
    `metadata` (vendor, product, protocol, source).
  - **PR #3 (Ken Buckler, Niagara):** NiagaraAX, Niagara4 and NiagaraN4 are kept as subject/issuer rules
    (1000101-106). The bare `Niagara` rule is dropped because it is a superset match. A negative pcap
    (`CN=Niagara Falls Tours`) asserts it stays quiet.
  - **PR #7 (Erwan Cordier, LOGO! brute force):** I fixed a real bug. The PR's `threshold:type limit, count 5,
    seconds 15` alerts on the *first* 5 attempts and then suppresses, which is the opposite of the stated "more than 5
    in 15 s". It is replaced with `detection_filter:track by_src, count 5, seconds 15`, matching the parsed
    `POST /AJAX` with a body starting `UAMCHAL:`. The body position is from the protocol write-up linked in the PR
    (jankeymeulen/siemens-logo-rest). This is SID 1000107.
- `tests/`: `pcapgen.py` builds full TCP sessions (handshake, ACKed data, FIN), HTTP and a hand-built TLS 1.2
  ClientHello/ServerHello/Certificate flight. The Ed25519 certs use a fixed key, and the pcaps are byte-reproducible.
  `cases.py` defines 73 cases: 56 positive and 17 negative. It writes the pcaps plus `expected.json`, which holds the
  exact SID set per case per engine with known prefix overlaps listed. `engine.sh` runs `-T` and then replays every
  pcap. `check.py` fails on any missing or extra alert, and on any rule SID with no positive case. `run.sh` runs
  everything in pinned containers.
- `.github/workflows/rules.yml` runs four checks: pull the pinned images, load-check the root Snort 2 files on both
  engines (and fail if Snort 3 reports duplicate SIDs), run `suricata -T` and `snort -T` on the new files, and run the
  pcap tests.
- `rules/README.md` covers usage, the change list, the SID map, known overlaps and how to run the tests.

## 3. Evidence

Engines: `jasonish/suricata:7.0.17` ("This is Suricata version 7.0.17 RELEASE"). Snort is
`ciscotalos/snort3@sha256:f15f714f...` ("Snort++ 3.10.0.0"). Python is 3.12 (uv) with scapy 2.8.0 and cryptography
50.0.2.

The upstream files as shipped, concatenated (`upstream/master`):
```
$ suricata -T -v -S all.rules            # rc=1
Info: detect: 1 rule files processed. 1 rules successfully loaded, 51 rules failed, 0
Error: suricata: Loading signatures failed.
$ snort -c snort.lua -R all.rules -T --warn-all    # rc=0 but:
WARNING: /l/master/all.rules:2 1:1 duplicates previous rule. Using revision 1.   (x51)
          duplicate rules: 51
port rule counts   tcp src 1             <- one ELITEWOLF rule actually active
```
Branch A, same commands:
```
$ suricata -T -v -S all.rules            # rc=0
Info: detect: 1 rule files processed. 52 rules successfully loaded, 0 rules failed, 0
Notice: suricata: Configuration provided was successfully loaded. Exiting.
$ snort ... -T                           # rc=0, no duplicate warnings
```
Branch B, `DOCKER="sudo docker" sh tests/run.sh` (trimmed):
```
wrote 73 pcaps to .../tests/out/pcaps
i: suricata: Configuration provided was successfully loaded. Exiting.
Snort successfully validated the configuration (with 1 warnings).     <- appid dir not configured (stock image)
ok   suricata pos_1000004: [1000001, 1000004]
ok   suricata pos_1000013_gzip_port8080: [1000013]
ok   suricata pos_1000022_issuer_only: [1000022]
ok   suricata pos_1000107_bruteforce: [1000107]
ok   suricata neg_logo_below_threshold: -
ok   suricata neg_logo_slow: -
ok   suricata neg_niagara_bare: -
ok   suricata neg_paths_in_request_only: -
ok   snort3   pos_1000013_gzip_port8080: [1000013]
ok   snort3   pos_1000016_in_body: -
...
suricata: 57 rules, 57 distinct SIDs fired across 73 pcaps
snort3: 51 rules, 51 distinct SIDs fired across 73 pcaps
0 failure(s)
```
Mutation check: injecting one extra alert into a negative case's results makes `check.py` print
`FAIL suricata neg_generic_http: want [] got [1000001]` and exit 1.

The first local run found a real engine difference. A raw `content` in a Snort 3 `alert http` rule does not see the
HTTP stream; only `http_header` / `http_raw_header` matched the err401 redirect (tested 6 buffer variants). Snort 3
SID 1000016 is therefore header-only. Suricata keeps the raw server-stream match (header or body). The
`pos_1000016_in_body` case records this difference explicitly.

GitHub Actions on the fork: green, see section 7.

## 4. Competing work check

`gh pr list -R nsacyber/ELITEWOLF --state all -L 50`, run at the start and again before finishing: #1 and #5
(RoseSecurity, closed unmerged), #3 (kenbuckler, Niagara, open since 2023-10-13) and #7 (biero-el-corridor, LOGO!,
open since 2024-01-07). None of them fixes SIDs; #5 rewrote rules but was closed. No PRs from the AI-spray accounts
(theyottaboy, rudycelekli, arpitjain099, arthurianresolve, ravisastryk, r3vpwnx). Issues: 0 open. Closed #4, #6 ("Add
context to your rules!") and #8 do not cover duplicate SIDs.

## 5. Draft upstream text (issue only; not filed)

**Title:** All rules use `sid:1`, so Suricata and Snort 3 load only one of the 52

**Body:**
> Every rule in the three `ELITEWOLF_SNORT_*.txt` files ends in `sid:1; rev:1;`. Engines key rules by gid:sid, so
> loading the files on a current sensor keeps one rule and discards the rest:
>
> - Suricata 7.0.17, `suricata -T -S <all three files>`: `1 rules successfully loaded, 51 rules failed` and
>   `Loading signatures failed` (exit 1).
> - Snort 3.10, `snort -T -R <all three files>`: 51 warnings `1:1 duplicates previous rule`, and only one rule ends up
>   active.
>
> SID 1 is also inside the range reserved for rules distributed with Snort.
>
> A minimal fix is to number the rules from the local range (1000000+). I have a one-commit change that does exactly
> that and nothing else (1000001-1000052 in file order, `rev:1` kept). With it, Suricata reports 52 rules loaded, 0
> failed, and Snort 3 loads them with no duplicate warnings:
> https://github.com/Dukotah/ELITEWOLF/tree/fix/unique-sids
>
> I understand from #3/#5 that the signatures are not being updated. I'm filing this so users who hit the load failure
> can find the cause. A community-maintained Snort 3/Suricata 7 port with a pcap test corpus is at
> https://github.com/Dukotah/ELITEWOLF/tree/lane/snort3-suricata7

No PR text is drafted: the maintainers have declined rule edits and left #3/#7 unanswered, so a PR would be noise. If
the owner wants one anyway, use title "Assign unique SIDs so the rule files load", reuse the issue body above, and end
it with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## 6. Land probability

**Low.** The maintainers told the community in writing that they are not updating the signatures. They have not merged
a PR in the project's lifetime, and they have left two community rule PRs unanswered for 2-3 years.

Owner next steps:
1. Decide whether to file the issue above (it is harmless and helps users who hit the load failure). Don't open a PR.
2. Optionally make `lane/snort3-suricata7` the fork's showcase: link `rules/README.md` from the fork description.
3. Optionally comment on #3 and #7 to tell the authors their rules are carried, with credit, in the fork. For #7, also
   point out the `threshold:type limit` bug.

## 7. CI

Workflow `rules` on `lane/snort3-suricata7`, run 44242337223:
https://github.com/Dukotah/ELITEWOLF/actions/runs/44242337223 (conclusion: **success**). Trimmed log:
```
Info: detect: 1 rule files processed. 52 rules successfully loaded, 0 rules failed, 0   <- legacy .txt, Suricata
Snort successfully validated the configuration (with 0 warnings).                        <- legacy .txt, Snort 3
wrote 73 pcaps to /home/runner/work/ELITEWOLF/ELITEWOLF/tests/out/pcaps
Snort successfully validated the configuration (with 1 warnings).                        <- rules/snort3
suricata: 57 rules, 57 distinct SIDs fired across 73 pcaps
snort3: 51 rules, 51 distinct SIDs fired across 73 pcaps
0 failure(s)
```
