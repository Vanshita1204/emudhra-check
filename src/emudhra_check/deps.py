"""Scan dependency files for Python packages that carry or load a vulnerable CA list."""
import json
import re
from pathlib import Path

from .data import CERTIFI_USERS, PYTHON_PACKAGES, SOFT_FLOORS
from .findings import FAIL, INFO, OK, UNKNOWN, WARN, Finding, cmp_versions, parse_version

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

LOCK_NAMES = ("poetry.lock", "uv.lock", "Pipfile.lock")


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirements(text):
    """Yield (name, spec) from requirements.txt / `pip freeze` text. spec is e.g. '==1.2.3'."""
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        line = line.split(";")[0].split("--hash")[0].strip()
        m = _REQ_RE.match(line)
        if m:
            yield norm(m.group(1)), m.group(3).replace(" ", "").rstrip("\\")


def _from_lock_toml(text):
    if tomllib is None:
        raise RuntimeError("TOML lockfiles need Python 3.11+")
    for pkg in tomllib.loads(text).get("package", []):
        if "name" in pkg and "version" in pkg:
            yield norm(pkg["name"]), "==" + str(pkg["version"])


def _from_pipfile_lock(text):
    data = json.loads(text)
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            yield norm(name), info.get("version", "")


def read_file(path):
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name in ("poetry.lock", "uv.lock"):
        return list(_from_lock_toml(text))
    if path.name == "Pipfile.lock":
        return list(_from_pipfile_lock(text))
    return list(parse_requirements(text))


def discover(directory):
    d = Path(directory)
    found = sorted(p for p in d.glob("requirements*.txt") if p.is_file())
    found += [d / n for n in LOCK_NAMES if (d / n).is_file()]
    return found


def classify(name, spec, minimum):
    """Return (level, message) for one watched package."""
    safe = parse_version(minimum)
    pin = re.search(r"(?:^|,)===?([0-9][^,;*]*)$|(?:^|,)===?([0-9][^,;*]*)(?:,|$)", spec)
    if pin and "*" not in spec:
        ver = pin.group(1) or pin.group(2)
        parsed = parse_version(ver)
        if parsed is None:
            return UNKNOWN, f"{name} {ver}: could not parse version (need >= {minimum})"
        if cmp_versions(parsed, safe) < 0:
            soft = parse_version(SOFT_FLOORS.get(name, ""))
            if soft and cmp_versions(parsed, soft) >= 0:
                return WARN, (f"{name} {ver} dropped the affected roots but also some unaffected emSign roots; "
                              f"{minimum} is the recommended release")
            return FAIL, f"{name} {ver} is older than the fixed version {minimum}"
        return OK, f"{name} {ver} (>= {minimum})"
    floor = re.search(r"(?:>=|~=)([0-9][^,;]*)", spec)
    if floor:
        parsed = parse_version(floor.group(1))
        if parsed and cmp_versions(parsed, safe) >= 0:
            return OK, f"{name}{spec}: lower bound already >= {minimum}"
        return WARN, f"{name}{spec}: allows versions older than {minimum}"
    return UNKNOWN, f"{name}{spec or ''}: not pinned, so the installed version decides (need >= {minimum})"


def scan_file(path):
    findings = []
    try:
        entries = read_file(path)
    except (OSError, ValueError, RuntimeError) as exc:
        return [Finding(UNKNOWN, "deps", str(path), f"could not read: {exc}")]
    seen = {}
    for name, spec in entries:
        seen.setdefault(name, spec)
    hit_any = False
    for name, minimum in PYTHON_PACKAGES.items():
        if name in seen:
            hit_any = True
            level, msg = classify(name, seen[name], minimum)
            fix = ""
            if level in (FAIL, WARN, UNKNOWN):
                fix = f"upgrade to {name}>={minimum} and re-lock/rebuild"
            findings.append(Finding(level, "deps", str(path), msg, fix))
    if "certifi" not in seen and CERTIFI_USERS & set(seen):
        users = ", ".join(sorted(CERTIFI_USERS & set(seen)))
        findings.append(Finding(
            INFO, "deps", str(path),
            f"certifi is not listed but is pulled in by {users}; this file cannot show its version",
            f"in the target environment run: python -m pip show certifi (need >= {PYTHON_PACKAGES['certifi']})"))
    elif not hit_any:
        findings.append(Finding(INFO, "deps", str(path),
                                f"none of {', '.join(PYTHON_PACKAGES)} are listed ({len(seen)} packages scanned)"))
    if "pip" not in seen:
        findings.append(Finding(
            INFO, "deps", str(path),
            "pip itself is rarely listed in dependency files, but pip < "
            f"{PYTHON_PACKAGES['pip']} always trusts its own bundled CA list",
            "run `emudhra-check env` against each interpreter, venv and container image"))
    return findings
