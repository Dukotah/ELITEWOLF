#!/usr/bin/env python3
"""Generate the synthetic pcap corpus and expected-alert table.

Usage: python3 tests/cases.py [outdir]   (default: tests/pcaps)

Writes <outdir>/<case>.pcap for every case below plus <outdir>/expected.json,
which maps each case to the exact set of SIDs each engine must raise. A
positive case names the rule(s) it targets; overlaps (one string being a
prefix of another rule's string) are listed explicitly. Negative cases expect
no alerts at all.
"""

import json
import os
import sys

from scapy.utils import wrpcap

import pcapgen as g

# Rules that exist only in the Suricata file (tls.cert_issuer has no Snort 3
# equivalent; the Snort 3 subject rule matches the raw certificate bytes).
ISSUER_SIDS = {1000022, 1000026, 1000052, 1000102, 1000104, 1000106}

CASES = []


def case(name, pkts, suricata, snort3=None, note=""):
    if snort3 is None:
        snort3 = [s for s in suricata if s not in ISSUER_SIDS]
    CASES.append({"name": name, "pkts": pkts, "suricata": sorted(suricata),
                  "snort3": sorted(snort3), "note": note})


def page(*paths, port=80, gz=False):
    return g.http_get("/", g.http_response(g.html_page(*paths), gzip_body=gz), port=port)


# ------------------------------------------------------- Rockwell (positive)
ROCKWELL = [
    (1000001, "/rokform/advancedDiags?pageReq=tcp", []),
    (1000002, "/rokform/SysDataDetail?name=eth0", []),
    (1000003, "/rokform/advancedDiags?pageReq=udptable", [1000010]),
    (1000004, "/rokform/advancedDiags?pageReq=tcpconn", [1000001]),
    (1000005, "/rokform/advancedDiags?pageReq=iproute", [1000012]),
    (1000006, "/rokform/advancedDiags?pageReq=genmem", []),
    (1000007, "/rokform/advancedDiags?pageReq=heap", []),
    (1000008, "/rokform/advancedDiags?pageReq=icmp", []),
    (1000009, "/rokform/advancedDiags?pageReq=arp", []),
    (1000010, "/rokform/advancedDiags?pageReq=udp", []),
    (1000011, "/rokform/advancedDiags?pageReq=if", []),
    (1000012, "/rokform/advancedDiags?pageReq=ip", []),
    (1000013, "/css/radevice.css", []),
    (1000014, "/rokform/SysListDetail?name=eth0", []),
]
for sid, path, also in ROCKWELL:
    case(f"pos_{sid}", page(path), [sid] + also)

# Same page served gzip-compressed on a non-standard port: the upstream raw
# port-80 rule could not see this; file.data / file_data decompress it.
case("pos_1000013_gzip_port8080", page("/css/radevice.css", port=8080, gz=True), [1000013],
     note="gzip body, HTTP on 8080")

# ------------------------------------------------------------ SEL (positive)
case("pos_1000015", page("/home.sel", port=80), [1000015])
case("pos_1000016", g.http_get(
    "/login.sel",
    g.http_response("", status="302 Found",
                    headers=["Location: /errors/err401.sel?username=admin"])),
    [1000016], note="redirect to the login error page")
case("pos_1000016_in_body", page("/errors/err401.sel?username=admin"), [1000016], snort3=[],
     note="Suricata matches the raw server stream; Snort 3 http_inspect only"
          " exposes it via http_header, so the Snort 3 rule is header-only")
case("pos_1000017", page("/default.sel"), [1000017])
case("pos_1000018", g.tcp_session(
    [("s", b"SSH-2.0-dropbear_2016.74\r\n"), ("c", b"SSH-2.0-OpenSSH_9.6\r\n")],
    sport=50022, dport=1024), [1000018])
case("pos_1000019", g.tcp_session(
    [("c", b"\x00\x00\x00\x08\x04\xd2\x16\x2f"), ("s", b"N SEL-3530 RTAC firmware R143\n")],
    sport=50432, dport=5432), [1000019])
case("pos_1000020_1000022", g.tls_session(g.make_cert("http://www.sel-secure.com")),
     [1000020, 1000022], note="self-signed: subject == issuer")
case("pos_1000020_subject_only", g.tls_session(
    g.make_cert("http://www.sel-secure.com", issuer_cn="Plant CA")), [1000020])
case("pos_1000022_issuer_only", g.tls_session(
    g.make_cert("rtac01.plant.local", issuer_cn="http://www.sel-secure.com")),
    [1000022], snort3=[1000020],
    note="Snort 3 has no issuer buffer; its raw-certificate rule 1000020 fires")
case("pos_1000023", page("/scripts/dScripts.sel"), [1000023])
case("pos_1000024", page("/css/sel.css?vid=20190101"), [1000024])
case("pos_1000025_1000026", g.tls_session(
    g.make_cert("http://www.selinc.com/EthernetCommunications/"), sni="10.10.0.10"),
    [1000025, 1000026])

def telnet(banner):
    return g.tcp_session([("s", banner), ("c", b"\r\n")], sport=50023, dport=23)

case("pos_1000027", telnet(b"\r\nSEL-751A\r\n=\r\n"), [1000027])
case("pos_1000028", telnet(b"Level 1\r\n=>"), [1000028])
case("pos_1000029", telnet(b"Level 2\r\n=>>"), [1000029])
case("pos_1000030", telnet(b"SEL-2032 COMMUNICATIONS PROCESSOR-S/N 1234567890\r\n"),
     [1000030, 1000027])
case("pos_1000031", telnet(b"Calibration Access Established\r\n==>"), [1000031])


def ftp(*cmds, replies=None):
    ex = [("s", b"220 FTP server ready\r\n")]
    for i, c in enumerate(cmds):
        ex.append(("c", c + b"\r\n"))
        ex.append(("s", (replies[i] if replies else b"200 OK") + b"\r\n"))
    return g.tcp_session(ex, sport=50021, dport=21)

FTP = [
    (1000032, b"USER 2AC", []),
    (1000033, b"CWD SEL-2701", []),
    (1000034, b"CWD /SEL-2701", []),
    (1000036, b"RETR DNPMAP.TXT", []),
    (1000037, b"STOR SET_DNP1.TXT", [1000038]),
    (1000038, b"STOR SET_P1.TXT", []),
    (1000039, b"USER ACC", []),
    (1000040, b"PASS otter", []),
    (1000041, b"STOR DNPMAP.TXT", []),
    (1000042, b"RETR ERR.TXT", []),
    (1000043, b"RETR SET_DNP1.TXT", [1000044]),
    (1000044, b"RETR SET_1.TXT", []),
    (1000045, b"USER FTPUSER", []),
    (1000046, b"PASS TAIL", []),
]
for sid, cmd, also in FTP:
    case(f"pos_{sid}", ftp(cmd), [sid] + also)
case("pos_1000035", ftp(b"PWD", replies=[b'257 "/SEL-2701" is current directory']), [1000035])
case("pos_1000047", g.tcp_session([("s", b"220 SEL-751A FTP SERVER ready\r\n"),
                                   ("c", b"QUIT\r\n"), ("s", b"221 Bye\r\n")],
                                  sport=50021, dport=21), [1000047])

# --------------------------------------------------------- Siemens (positive)
case("pos_1000048", page("/CSS/S7Web.css"), [1000048])
case("pos_1000049", page("/Images/CPU1200/cpu.png"), [1000049])
case("pos_1000050_1000052", g.tls_session(g.make_cert("S7-1200 Controller Family")),
     [1000050, 1000052])
case("pos_1000050_in_O", g.tls_session(
    g.make_cert("plc01", issuer_cn="Plant CA", subject_o="S7-1200 Controller Family")),
    [1000050], note="string in subject O, not CN")


def logo_attempts(n, dt=1.0):
    clock = g.Clock()
    pkts = []
    for i in range(n):
        body = f"UAMCHAL:3,4,{1234567890 + i},2345678901,3456789012,456789012".encode()
        req = g.http_request("POST", "/AJAX", headers=["Security-Hint: p"], body=body)
        pkts += g.tcp_session([("c", req), ("s", g.http_response("700,ABCDEF,567890123",
                                                                 ctype="text/plain"))],
                              sport=51000 + i, dport=80, clock=clock)
        clock.tick(dt)
    return pkts

case("pos_1000107_bruteforce", logo_attempts(7), [1000107],
     note="7 login challenges in ~7 s; detection_filter alerts from the 6th")

# ---------------------------------------------------------- Niagara (PR #3)
case("pos_1000101_1000102", g.tls_session(g.make_cert("NiagaraAX")), [1000101, 1000102])
case("pos_1000103_1000104", g.tls_session(g.make_cert("Niagara4")), [1000103, 1000104])
case("pos_1000105_1000106", g.tls_session(g.make_cert("NiagaraN4")), [1000105, 1000106])

# ------------------------------------------------------------------ negatives
case("neg_generic_http", page("/index.html", "/css/site.css", "/images/logo.png"), [])
case("neg_rokform_other_page", page("/rokform/login", "/rokform/advancedDiags?pageReq=mem"), [])
case("neg_paths_in_request_only", g.tcp_session(
    [("c", g.http_request(uri="/home.sel")), ("s", g.http_response("<html>ok</html>"))]
    + [("c", g.http_request(uri="/css/radevice.css")), ("s", g.http_response("ok"))],
    sport=42000, dport=80), [],
    note="client asks for device paths; rules are server-side by design")
case("neg_paths_case_mismatch", page("/HOME.SEL", "/css/S7web.css", "/images/cpu1200/"), [])
case("neg_generic_tls", g.tls_session(g.make_cert("www.example.com"), sni="www.example.com"), [])
case("neg_tls_ca_name", g.tls_session(g.make_cert("scada.plant.local", issuer_cn="Siemens Plant CA")), [])
case("neg_niagara_bare", g.tls_session(g.make_cert("Niagara Falls Tours")), [],
     note="the dropped bare-'Niagara' rule from PR #3 would have fired here")
case("neg_ssh_other_version", g.tcp_session(
    [("s", b"SSH-2.0-dropbear_2020.81\r\n"), ("c", b"SSH-2.0-OpenSSH_9.6\r\n")],
    sport=50022, dport=1024), [])
case("neg_ssh_dropbear_port22", g.tcp_session(
    [("s", b"SSH-2.0-dropbear_2016.74\r\n"), ("c", b"SSH-2.0-OpenSSH_9.6\r\n")],
    sport=50022, dport=22), [])
case("neg_telnet_linux", telnet(b"Ubuntu 24.04 LTS\r\nlogin: "), [])
case("neg_telnet_client_types_level", g.tcp_session(
    [("s", b"login: "), ("c", b"Level 1\r\n"), ("c", b"Level 2\r\n")],
    sport=50023, dport=23), [], note="strings sent by the client, not the device")
case("neg_ftp_anonymous", ftp(b"USER anonymous", b"PASS guest@", b"RETR readme.txt",
                              b"STOR upload.TXT"), [])
case("neg_ftp_lowercase_settings", ftp(b"STOR set_p1.txt", b"RETR set_p1.txt"), [])
case("neg_ftp_strings_from_server", g.tcp_session(
    [("s", b"220 USER 2AC RETR DNPMAP.TXT PASS otter\r\n"), ("c", b"QUIT\r\n")],
    sport=50021, dport=21), [], note="command strings in the server direction")
case("neg_logo_below_threshold", logo_attempts(5), [],
     note="5 attempts: count 5 is not exceeded")
case("neg_logo_slow", logo_attempts(7, dt=10.0), [],
     note="7 attempts spread over ~70 s never exceed 5 per 15 s")
case("neg_logo_get_ajax", g.http_get("/AJAX", g.http_response("700", ctype="text/plain")), [])


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "pcaps")
    os.makedirs(outdir, exist_ok=True)
    expected = {}
    for c in CASES:
        wrpcap(os.path.join(outdir, c["name"] + ".pcap"), c["pkts"])
        expected[c["name"]] = {"suricata": c["suricata"], "snort3": c["snort3"],
                               "note": c["note"]}
    with open(os.path.join(outdir, "expected.json"), "w", newline="\n") as f:
        json.dump(expected, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"wrote {len(CASES)} pcaps to {outdir}")


if __name__ == "__main__":
    main()
