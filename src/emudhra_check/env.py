"""Check this machine: pip/certifi in a Python interpreter, CA bundles, OS trust store, runtimes."""
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from .data import (PATCHED_GO, PATCHED_JAVA, PATCHED_JAVA8_UPDATE, PATCHED_NODE, PATCHED_PYTHON,
                   PYTHON_PACKAGES, ROOT_BY_CERT, SOFT_FLOORS)
from .der import cert_fingerprint, pem_to_ders
from .weakkey import tiny_private_key
from .findings import FAIL, INFO, OK, UNKNOWN, WARN, Finding, cmp_versions, parse_version

# Runs inside the interpreter being checked. Prints one JSON line. Must not import
# anything from the project directory (the caller passes -I).
PROBE = r"""
import json, sys
out = {"version": list(sys.version_info[:3]), "executable": sys.executable}
try:
    from importlib import metadata as m
except Exception:
    m = None
for name in ("pip", "certifi", "uv"):
    try:
        out[name] = m.version(name) if m else None
    except Exception:
        out[name] = None
try:
    import certifi
    out["certifi_path"] = certifi.where()
except Exception:
    out["certifi_path"] = None
try:
    import os, importlib.util
    spec = importlib.util.find_spec("pip")
    base = os.path.dirname(spec.origin) if spec and spec.origin else None
    cand = os.path.join(base, "_vendor", "certifi", "cacert.pem") if base else None
    out["pip_bundle"] = cand if cand and os.path.exists(cand) else None
except Exception:
    out["pip_bundle"] = None
print(json.dumps(out))
"""


def scan_bundle_text(text):
    """Return {cert_sha256: (name, role)} for distrusted/noted roots and tiny-key CAs found in PEM text."""
    hits = {}
    for der in pem_to_ders(text):
        fp = cert_fingerprint(der)
        if fp in ROOT_BY_CERT:
            hits[fp] = ROOT_BY_CERT[fp]
            continue
        k = tiny_private_key(der)
        if k:
            hits[fp] = (f"certificate {fp[:16]}... (key = {k}*G)", "weak")
    return hits


def scan_bundle(path):
    """Like scan_bundle_text for a file; None if it cannot be read."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return scan_bundle_text(text)


def judge_bundle(label, where, hits, area="env"):
    """Findings for one CA bundle. hits is scan_bundle's result (None = unreadable)."""
    if hits is None:
        return [Finding(UNKNOWN, area, label, f"could not read {where}")]
    out = []
    bad = sorted({n for n, role in hits.values() if role == "distrust"})
    note = sorted({n for n, role in hits.values() if role == "note"})
    weak = sorted({n for n, role in hits.values() if role == "weak"})
    if weak:
        out.append(Finding(FAIL, area, label,
                           f"{where} contains a CA whose private key is a tiny integer (anyone can recover it): "
                           f"{'; '.join(weak)}",
                           "remove this certificate from the bundle; it can sign anything"))
    if bad:
        out.append(Finding(FAIL, area, label, f"{where} still trusts: {', '.join(bad)}",
                           "update this CA bundle (or the package that ships it)"))
    if note:
        out.append(Finding(
            WARN, area, label,
            f"{where} contains the Sectigo 'AAA Certificate Services' root, the only path for the cross-signed "
            "copies of the weak keys (Chrome and Mozilla already dropped it; Windows and Apple still trust it)",
            "fine if your client checks revocation; otherwise see the workarounds at "
            "https://emudhra.we-have-a-problem.com/#workarounds"))
    if not bad and not note and not weak:
        out.append(Finding(OK, area, label, f"{where}: no affected roots present"))
    return out


def _bundle_findings(label, path):
    return judge_bundle(label, path, scan_bundle(path))


def probe_python(python):
    try:
        proc = subprocess.run([python, "-I", "-c", PROBE], capture_output=True, text=True, timeout=30)
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


def judge_cpython(ver, label, area="env"):
    out = []
    vstr = ".".join(map(str, ver))
    patched = PATCHED_PYTHON.get(ver[:2])
    if patched:
        if cmp_versions(ver, patched) < 0:
            out.append(Finding(WARN, area, label, f"CPython {vstr} predates the patched {'.'.join(map(str, patched))} "
                               "(new venvs get an old pip via ensurepip)",
                               "upgrade CPython, or upgrade pip inside every new venv"))
        else:
            out.append(Finding(OK, area, label, f"CPython {vstr} is a patched release"))
    else:
        out.append(Finding(INFO, area, label,
                           f"CPython {vstr}: no patched release listed for this line; ensurepip may ship an old pip"))
    return out


def check_python(python):
    info = probe_python(python)
    label = f"python {python}"
    if info is None:
        return [Finding(UNKNOWN, "env", label, "could not run this interpreter")]
    out = judge_cpython(tuple(info["version"]), label)
    for pkg, minimum in PYTHON_PACKAGES.items():
        if pkg not in ("pip", "certifi", "uv"):
            continue
        got = info.get(pkg)
        if not got:
            continue
        parsed = parse_version(got)
        soft = parse_version(SOFT_FLOORS.get(pkg, ""))
        if parsed and soft and cmp_versions(soft, parsed) <= 0 and cmp_versions(parsed, parse_version(minimum)) < 0:
            out.append(Finding(WARN, "env", label,
                               f"{pkg} {got} dropped the affected roots but also some unaffected emSign roots",
                               f"upgrade to {pkg} {minimum} (recommended)"))
        elif parsed and cmp_versions(parsed, parse_version(minimum)) < 0:
            out.append(Finding(FAIL, "env", label, f"{pkg} {got} is older than {minimum}",
                               f"upgrade {pkg} (bootstrap pip safely first: see "
                               "https://discuss.python.org/t/109576)"))
        else:
            out.append(Finding(OK, "env", label, f"{pkg} {got} (>= {minimum})"))
    if info.get("pip_bundle"):
        out += _bundle_findings(f"{label} pip's bundled CA list", info["pip_bundle"])
    if info.get("certifi_path"):
        out += _bundle_findings(f"{label} certifi bundle", info["certifi_path"])
    return out


def check_trust_stores():
    out = []
    if sys.platform == "win32" and hasattr(ssl, "enum_certificates"):
        bad = set()
        for store in ("ROOT", "CA"):
            try:
                for der, enc, _trust in ssl.enum_certificates(store):
                    if enc == "x509_asn" and cert_fingerprint(der) in ROOT_BY_CERT:
                        bad.add(ROOT_BY_CERT[cert_fingerprint(der)])
            except OSError:
                pass
        distrust = sorted(n for n, r in bad if r == "distrust")
        if distrust:
            out.append(Finding(FAIL, "env", "Windows certificate store", f"still trusts: {', '.join(distrust)}",
                               "run Windows Update; Microsoft blocks these via its trust list"))
        else:
            out.append(Finding(OK, "env", "Windows certificate store", "no distrusted emSign roots in ROOT/CA"))
        return out
    paths = ssl.get_default_verify_paths()
    seen = set()
    for candidate in (paths.cafile, paths.openssl_cafile, "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
                      "/etc/pki/tls/certs/ca-bundle.crt"):
        if candidate and candidate not in seen and os.path.isfile(candidate):
            seen.add(candidate)
            out += _bundle_findings("system CA bundle", candidate)
    if not seen:
        out.append(Finding(UNKNOWN, "env", "system CA bundle", "no system CA bundle file found to inspect"))
    for var in ("PIP_CERT", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
        val = os.environ.get(var)
        if val and os.path.isfile(val):
            out += _bundle_findings(f"${var}", val)
    return out


def _run(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return None


def judge_node(text, area="env", label=None):
    v = parse_version(text)
    if not v:
        return []
    label = label or f"node {text}"
    fix = PATCHED_NODE.get(v[0])
    if fix is None:
        return [Finding(INFO, area, label, "no fix listed for this Node line; use a listed release line")]
    if cmp_versions(v, fix) < 0:
        return [Finding(FAIL, area, label, f"older than the patched {'.'.join(map(str, fix))}", "upgrade Node.js")]
    return [Finding(OK, area, label, "patched release")]


def judge_go(text, area="env", label=None):
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", text)
    v = parse_version(m.group(1)) if m else None
    if not v:
        return []
    label = label or text
    fix = PATCHED_GO.get(v[:2])
    if fix is None:
        return [Finding(INFO, area, label, "no fix listed for this Go line; upgrade to 1.26.10+ / 1.27.3+ and rebuild")]
    if cmp_versions(v, fix) < 0:
        return [Finding(FAIL, area, label, f"older than the patched {'.'.join(map(str, fix))}",
                        "upgrade Go and rebuild your binaries")]
    return [Finding(OK, area, label, "patched toolchain (binaries built earlier must be rebuilt)")]


def judge_java(raw, area="env", label=None):
    label = label or f"java {raw}"
    if raw.startswith("1.8"):
        upd = re.search(r"_(\d+)", raw)
        if upd and int(upd.group(1)) < PATCHED_JAVA8_UPDATE:
            return [Finding(FAIL, area, label, f"older than 8u{PATCHED_JAVA8_UPDATE}", "upgrade the JDK/JRE")]
        if upd:
            return [Finding(OK, area, label, "patched release")]
        return []
    v = parse_version(raw)
    fix = PATCHED_JAVA.get(v[0]) if v else None
    if fix is None:
        return [Finding(INFO, area, label, "no fix listed for this Java line")]
    c = cmp_versions((v + (0, 0, 0))[:3], fix)
    if c < 0:
        return [Finding(FAIL, area, label, f"older than the patched {'.'.join(map(str, fix))}", "upgrade the JDK/JRE")]
    if c == 0:
        return [Finding(UNKNOWN, area, label,
                        "matches the patched release number; vendors use different build suffixes",
                        "confirm your vendor's build against https://emudhra.we-have-a-problem.com/#patched-runtimes")]
    return [Finding(OK, area, label, "newer than the patched release")]


def check_runtimes():
    out = []
    if shutil.which("node"):
        out += judge_node(_run(["node", "--version"]) or "")
    if shutil.which("go"):
        out += judge_go(_run(["go", "version"]) or "")
    if shutil.which("java"):
        m = re.search(r'version "([^"]+)"', _run(["java", "-version"]) or "")
        if m:
            out += judge_java(m.group(1))
    return out


def check_env(pythons=None):
    findings = []
    for py in (pythons or [sys.executable]):
        findings += check_python(py)
    findings += check_trust_stores()
    findings += check_runtimes()
    return findings
