"""Deterministic synthetic pcap builders for the ELITEWOLF rule tests.

Everything here is synthetic: no vendor traffic is used. Each builder returns a
list of scapy packets for one or more complete TCP sessions (handshake, data,
ACKs, FIN) so that both Suricata and Snort 3 reassemble the stream and run
their application-layer parsers over it.

Output is byte-for-byte reproducible: timestamps, ISNs, TLS randoms and the
certificate signing key are all fixed.
"""

import datetime
import gzip
import struct

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

EPOCH = 1700000000.0
MSS = 1400

CLIENT = "10.10.0.20"
SERVER = "10.10.0.10"


class Clock:
    """Monotonic fake clock so packets and sessions get distinct timestamps."""

    def __init__(self, start=EPOCH):
        self.t = start

    def tick(self, dt=0.001):
        self.t += dt
        return self.t


def tcp_session(exchanges, sport, dport, client=CLIENT, server=SERVER,
                clock=None, isn_c=1000, isn_s=5000):
    """Build one TCP session.

    exchanges is a list of (direction, payload) with direction "c" for
    client->server and "s" for server->client. Payloads larger than MSS are
    split into several segments; every data segment is ACKed.
    """
    clock = clock or Clock()
    eth_c = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    eth_s = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    pkts = []

    def c2s(flags, seq, ack, data=b""):
        p = eth_c / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=65535)
        if data:
            p = p / data
        p.time = clock.tick()
        pkts.append(p)

    def s2c(flags, seq, ack, data=b""):
        p = eth_s / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags=flags, seq=seq, ack=ack, window=65535)
        if data:
            p = p / data
        p.time = clock.tick()
        pkts.append(p)

    cseq, sseq = isn_c, isn_s
    c2s("S", cseq, 0)
    s2c("SA", sseq, cseq + 1)
    cseq += 1
    sseq += 1
    c2s("A", cseq, sseq)

    for direction, payload in exchanges:
        for i in range(0, len(payload), MSS):
            chunk = payload[i:i + MSS]
            if direction == "c":
                c2s("PA", cseq, sseq, chunk)
                cseq += len(chunk)
                s2c("A", sseq, cseq)
            else:
                s2c("PA", sseq, cseq, chunk)
                sseq += len(chunk)
                c2s("A", cseq, sseq)

    c2s("FA", cseq, sseq)
    s2c("FA", sseq, cseq + 1)
    cseq += 1
    sseq += 1
    c2s("A", cseq, sseq)
    return pkts


# --------------------------------------------------------------------- HTTP

def http_request(method="GET", uri="/", host="10.10.0.10", headers=(), body=b""):
    lines = [f"{method} {uri} HTTP/1.1", f"Host: {host}",
             "User-Agent: Mozilla/5.0", "Accept: */*"]
    lines += list(headers)
    if body or method == "POST":
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(body, status="200 OK", ctype="text/html", headers=(), gzip_body=False):
    if isinstance(body, str):
        body = body.encode()
    extra = list(headers)
    if gzip_body:
        body = gzip.compress(body, mtime=0)
        extra.append("Content-Encoding: gzip")
    lines = [f"HTTP/1.1 {status}", "Server: embedded", f"Content-Type: {ctype}",
             f"Content-Length: {len(body)}", "Connection: close"] + extra
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def html_page(*paths, title="Device"):
    """An HTML page that references each of the given paths."""
    links = []
    for p in paths:
        if p.endswith(".css") or ".css?" in p:
            links.append(f'<link rel="stylesheet" href="{p}">')
        elif p.endswith(".js") or ".sel" in p and "scripts" in p:
            links.append(f'<script src="{p}"></script>')
        else:
            links.append(f'<a href="{p}">{p}</a>')
    return ("<!DOCTYPE html><html><head><title>" + title + "</title>"
            + "".join(links) + "</head><body><p>status</p></body></html>")


def http_get(uri, response, port=80, clock=None):
    return tcp_session([("c", http_request(uri=uri)), ("s", response)],
                       sport=40000 + port % 1000, dport=port, clock=clock)


# ---------------------------------------------------------------------- TLS

_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def make_cert(subject_cn, issuer_cn=None, subject_o=None):
    """DER certificate with the given subject/issuer CN, signed by a fixed key."""
    issuer_cn = issuer_cn or subject_cn

    def name(cn, o=None):
        attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US")]
        if o:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        return x509.Name(attrs)

    cert = (x509.CertificateBuilder()
            .subject_name(name(subject_cn, subject_o))
            .issuer_name(name(issuer_cn))
            .public_key(_KEY.public_key())
            .serial_number(0x1E1E)
            .not_valid_before(datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2043, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(_KEY, None))
    return cert.public_bytes(serialization.Encoding.DER)


def _u24(n):
    return struct.pack(">I", n)[1:]


def _hs(msg_type, body):
    return bytes([msg_type]) + _u24(len(body)) + body


def _record(content_type, payload):
    return bytes([content_type]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def tls_client_hello(sni=None):
    exts = b""
    if sni:
        name = sni.encode()
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        lst = struct.pack(">H", len(entry)) + entry
        exts += b"\x00\x00" + struct.pack(">H", len(lst)) + lst
    # signature_algorithms (ed25519, rsa_pkcs1_sha256)
    sa = b"\x08\x07\x04\x01"
    exts += b"\x00\x0d" + struct.pack(">H", len(sa) + 2) + struct.pack(">H", len(sa)) + sa
    body = (b"\x03\x03" + bytes(32) + b"\x00"
            + b"\x00\x04\xc0\x2f\x00\x9c" + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    return _record(22, _hs(1, body))


def tls_server_flight(cert_der):
    server_hello = _hs(2, b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\xc0\x2f" + b"\x00")
    cert_entry = _u24(len(cert_der)) + cert_der
    certificate = _hs(11, _u24(len(cert_entry)) + cert_entry)
    done = _hs(14, b"")
    return _record(22, server_hello + certificate + done)


def tls_session(cert_der, sni=None, port=443, clock=None):
    """TLS 1.2 handshake up to ServerHelloDone, carrying the given certificate."""
    return tcp_session([("c", tls_client_hello(sni)), ("s", tls_server_flight(cert_der))],
                       sport=41000 + port % 1000, dport=port, clock=clock)
