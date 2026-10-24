"""Fetch a server's certificate chain and look for the compromised eMudhra keys."""
import base64
import os
import shutil
import socket
import ssl
import subprocess

from urllib.parse import unquote, urlparse

from .data import CERT_TO_NAME, INTERMEDIATES, ROOT_BY_CERT, ROOT_BY_SPKI, ROOTS, SPKI_TO_NAME
from .der import cert_fingerprint, parse_cert, pem_to_ders, sha256_hex
from .findings import FAIL, INFO, OK, UNKNOWN, Finding

_COMPROMISED_NAMES = [n.encode() for n, *_ in INTERMEDIATES]
_DISTRUST_NAMES = {n.encode(): n for n, role, *_ in ROOTS if role == "distrust"}

FIX_FAIL = ("get a new certificate from a CA in a different hierarchy (eMudhra's G1 RSA roots "
            "or another CA), install the full new chain, and re-run this check")


def _to_der(cert):
    if isinstance(cert, (bytes, bytearray)):
        return bytes(cert)
    if isinstance(cert, str):
        return pem_to_ders(cert)[0]
    return cert.public_bytes(ssl._ssl.ENCODING_DER)  # _ssl.Certificate object


def _open_socket(host, port, timeout):
    """TCP connection, tunnelled through $HTTPS_PROXY (HTTP CONNECT) when one is set."""
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    no_proxy = (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").split(",")
    if not proxy or any(n.strip() and host.endswith(n.strip().lstrip("*")) for n in no_proxy):
        return socket.create_connection((host, port), timeout=timeout)
    u = urlparse(proxy if "//" in proxy else "//" + proxy)
    sock = socket.create_connection((u.hostname, u.port or 8080), timeout=timeout)
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if u.username:
        cred = base64.b64encode(f"{unquote(u.username)}:{unquote(u.password or '')}".encode()).decode()
        req += f"Proxy-Authorization: Basic {cred}\r\n"
    sock.sendall((req + "\r\n").encode())
    reply = b""
    while b"\r\n\r\n" not in reply and len(reply) < 8192:
        part = sock.recv(1024)
        if not part:
            break
        reply += part
    status = reply.split(b"\r\n", 1)[0].decode("latin-1")
    if " 200" not in status:
        sock.close()
        raise OSError(f"proxy refused CONNECT to {host}:{port} ({status or 'no reply'})")
    return sock


def fetch_chain(host, port=443, timeout=8.0):
    """Return the DER certificates the server sends (not validated, order as sent)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect whatever is served, even if untrusted
    if hasattr(ssl.SSLSocket, "get_unverified_chain"):  # Python 3.13+
        with _open_socket(host, port, timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                chain = tls.get_unverified_chain()
        return [_to_der(c) for c in chain]
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("Python < 3.13 needs the openssl command-line tool to read the chain")
    proc = subprocess.run(
        [exe, "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
        input=b"", capture_output=True, timeout=timeout + 5)
    ders = pem_to_ders(proc.stdout.decode("utf-8", "replace"))
    if not ders:
        raise RuntimeError("no certificates returned (" + proc.stderr.decode("utf-8", "replace").strip()[:200] + ")")
    return ders


def analyze_chain(ders, subject="chain"):
    """Check DER certificates against the compromised keys. Returns a list of Findings."""
    findings = []
    for idx, der in enumerate(ders):
        label = "leaf" if idx == 0 else f"intermediate/root #{idx}"
        try:
            info = parse_cert(der)
        except ValueError as exc:
            findings.append(Finding(UNKNOWN, "domain", subject, f"cert #{idx} unreadable: {exc}"))
            continue
        spki, fp = sha256_hex(info["spki"]), cert_fingerprint(der)
        if spki in SPKI_TO_NAME or fp in CERT_TO_NAME:
            name = CERT_TO_NAME.get(fp) or SPKI_TO_NAME[spki]
            findings.append(Finding(
                FAIL, "domain", subject,
                f"{label} uses the compromised key of '{name}' (private key is public knowledge; certificate is revoked)",
                FIX_FAIL))
            continue
        root = ROOT_BY_CERT.get(fp) or ROOT_BY_SPKI.get(spki)
        if root and root[1] == "distrust":
            findings.append(Finding(
                FAIL, "domain", subject,
                f"{label} is '{root[0]}', a root that Mozilla has removed and Chrome is removing", FIX_FAIL))
            continue
        issuer = info["issuer"]
        bad_issuer = next((n for n in _COMPROMISED_NAMES if n in issuer), None)
        if bad_issuer:
            findings.append(Finding(
                FAIL, "domain", subject,
                f"{label} was issued by '{bad_issuer.decode()}', one of the eight compromised intermediates",
                FIX_FAIL))
            continue
        root_issuer = next((v for k, v in _DISTRUST_NAMES.items() if k in issuer), None)
        if root_issuer:
            findings.append(Finding(
                FAIL, "domain", subject, f"{label} was issued directly by '{root_issuer}', a distrusted root", FIX_FAIL))
    if not any(f.level == FAIL for f in findings):
        findings.append(Finding(
            OK, "domain", subject,
            f"{len(ders)} certificate(s) served; none use the compromised keys or the distrusted emSign roots",
            ""))
        findings.append(Finding(
            INFO, "domain", subject,
            "this inspects the chain the server sends; a server that omits its intermediates, or a client "
            "that builds a different path, is not visible here"))
    return findings


def check_host(target, timeout=8.0):
    host, _, port = target.partition(":")
    port = int(port) if port.isdigit() else 443
    subject = f"{host}:{port}"
    try:
        ders = fetch_chain(host, port, timeout)
    except (OSError, RuntimeError, ssl.SSLError, subprocess.TimeoutExpired) as exc:
        return [Finding(UNKNOWN, "domain", subject, f"could not fetch certificate chain: {exc}")]
    return analyze_chain(ders, subject)
