"""Check container images without running them.

Reads a Docker (`docker save`) or OCI image archive, replays the layers in memory
(honouring whiteouts) and inspects the resulting filesystem for CA bundles, Python
packages and runtime versions. Nothing is extracted to disk; archives are untrusted
input, so only a few well-known paths are ever read, each with a size cap.
"""
import json
import os
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zlib

from .data import PYTHON_PACKAGES
from .deps import classify, norm
from .env import (judge_bundle, judge_cpython, judge_go, judge_java, judge_node, scan_bundle_text)
from .findings import INFO, OK, UNKNOWN, Finding, parse_version

AREA = "image"
MAX_READ = 16 * 1024 * 1024
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

BUNDLE_NAMES = frozenset({"cacert.pem", "ca-certificates.crt", "ca-bundle.crt", "ca-bundle.pem",
                          "tls-ca-bundle.pem", "cert.pem"})
CERT_DIRS = ("usr/share/ca-certificates/", "usr/local/share/ca-certificates/", "etc/ssl/certs/",
             "etc/pki/ca-trust/source/anchors/")
_PKG_RE = re.compile(r"(?:^|/)(?:site|dist)-packages/([^/]+)\.(?:dist|egg)-info/(?:METADATA|PKG-INFO)$")
_NAMEVER_RE = re.compile(r"^(.+?)-(\d.*)$")
_GO_RE = re.compile(r"(?:^|/)go/VERSION$")
_JAVA_DIR_RE = re.compile(r"jdk|jre|jvm|java", re.I)
READ_KINDS = ("bundle", "cert", "go", "java")


class ImageError(Exception):
    pass


def _norm(name):
    return posixpath.normpath("/" + name).lstrip("/")


def classify_path(p):
    """What a file in an image is for, or None if we do not care about it."""
    base = posixpath.basename(p)
    if base in BUNDLE_NAMES:
        return "bundle"
    if p.endswith((".crt", ".pem")) and p.startswith(CERT_DIRS):
        return "cert"
    if _PKG_RE.search(p):
        return "pkg"
    if _GO_RE.search(p):
        return "go"
    if base == "release" and _JAVA_DIR_RE.search(posixpath.dirname(p)):
        return "java"
    return None


# ---- archive formats -------------------------------------------------------------------------

def _read_json(tar, members, name):
    info = members.get(_norm(name))
    f = tar.extractfile(info) if info is not None else None
    if f is None:
        raise ImageError(f"{name} is missing from the archive")
    try:
        return json.loads(f.read(MAX_READ))
    except ValueError as exc:
        raise ImageError(f"{name} is not valid JSON: {exc}")


def _blob_name(digest):
    return "blobs/" + digest.replace(":", "/")


def _oci_images(tar, members, index, images, skipped, label_hint="", depth=0):
    for desc in index.get("manifests", []):
        digest = desc.get("digest", "")
        if _norm(_blob_name(digest)) not in members:
            skipped.append(f"{label_hint or digest[:19]}: manifest blob not in archive")
            continue
        doc = _read_json(tar, members, _blob_name(digest))
        ann = desc.get("annotations") or {}
        hint = ann.get("io.containerd.image.name") or ann.get("org.opencontainers.image.ref.name") or label_hint
        if "manifests" in doc:
            if depth < 4:
                _oci_images(tar, members, doc, images, skipped, hint, depth + 1)
            continue
        plat = desc.get("platform") or {}
        if "layers" not in doc or plat.get("os") == "unknown":  # attestation / non-image manifest
            continue
        label = hint or digest[:19]
        if plat.get("os") and plat.get("architecture"):
            label += f" ({plat['os']}/{plat['architecture']})"
        layers = [_blob_name(layer["digest"]) for layer in doc["layers"]]
        cfg_name = _blob_name(doc["config"]["digest"])
        absent = [n for n in layers + [cfg_name] if _norm(n) not in members]
        if absent:
            skipped.append(f"{label}: {len(absent)} blob(s) not in archive (platform not pulled?)")
            continue
        images.append((label, _read_json(tar, members, cfg_name), layers))


def load_images(tar, members):
    """Return ([(label, config, [layer names])], [skipped notes]) for an opened archive."""
    images, skipped = [], []
    if "manifest.json" in members:
        for ent in _read_json(tar, members, "manifest.json"):
            label = (ent.get("RepoTags") or [None])[0] or ent["Config"]
            images.append((label, _read_json(tar, members, ent["Config"]), ent["Layers"]))
    elif "index.json" in members:
        _oci_images(tar, members, _read_json(tar, members, "index.json"), images, skipped)
    else:
        raise ImageError("not a Docker or OCI image archive (no manifest.json or index.json); "
                         "create one with `docker save IMAGE -o image.tar`")
    return images, skipped


# ---- layer replay ----------------------------------------------------------------------------

def _drop(state, prefix_ok):
    for p in [p for p in state if prefix_ok(p)]:
        del state[p]


def _apply_layer(state, fileobj):
    """Apply one layer to `state` ({path: (kind, data)}), which only tracks files we care about."""
    head = fileobj.read(4)
    fileobj.seek(0)
    if head == ZSTD_MAGIC:
        raise ImageError("zstd-compressed layers are not supported (standard library only); "
                         "re-export with `docker save` or use gzip layers")
    added, whiteouts, opaque, overwritten = {}, [], [], []
    with tarfile.open(fileobj=fileobj, mode="r|*") as layer:
        for m in layer:
            p = _norm(m.name)
            d, base = posixpath.split(p)
            if base == ".wh..wh..opq":
                opaque.append(d)
                continue
            if base.startswith(".wh."):
                whiteouts.append(posixpath.join(d, base[4:]))
                continue
            if p in state:
                overwritten.append(p)
            kind = classify_path(p) if m.isreg() else None
            if kind is None:
                continue
            data = None
            if kind in READ_KINDS:
                if m.size > MAX_READ:
                    continue
                data = layer.extractfile(m).read()
            added[p] = (kind, data)
    # Whiteouts and overwrites only affect lower layers, so they run before this layer's own files land.
    for w in whiteouts:
        _drop(state, lambda p, w=w: p == w or p.startswith(w + "/"))
    for o in opaque:
        _drop(state, lambda p, o=o: p.startswith(o + "/") if o else True)
    for p in overwritten:
        state.pop(p, None)
    state.update(added)


def replay(tar, members, layers):
    state = {}
    for name in layers:
        info = members.get(_norm(name))
        f = tar.extractfile(info) if info is not None else None
        if f is None:
            raise ImageError(f"layer {name} is missing from the archive")
        _apply_layer(state, f)
    return state


# ---- judging ---------------------------------------------------------------------------------

def _text(data):
    return data.decode("utf-8", errors="replace")


def _config_env(config):
    out = {}
    for kv in (config.get("config") or {}).get("Env") or []:
        k, sep, v = kv.partition("=")
        if sep:
            out[k] = v
    return out


def judge_filesystem(label, config, state):
    out = []
    cenv = _config_env(config)
    out.append(Finding(INFO, AREA, label, f"{config.get('os', '?')}/{config.get('architecture', '?')}"))

    bundles = sorted(p for p, (k, _) in state.items() if k == "bundle")
    certs = sorted(p for p, (k, _) in state.items() if k == "cert")
    for p in bundles:
        out += judge_bundle(f"{label}: CA bundle", "/" + p, scan_bundle_text(_text(state[p][1])), AREA)
    cert_bad = 0
    for p in certs:
        hits = scan_bundle_text(_text(state[p][1]))
        if hits:
            cert_bad += 1
            out += judge_bundle(f"{label}: CA certificate", "/" + p, hits, AREA)
    if certs and not cert_bad:
        out.append(Finding(OK, AREA, f"{label}: CA certificates",
                           f"{len(certs)} individual CA files (e.g. /usr/share/ca-certificates): no affected roots present"))
    if not bundles and not certs:
        out.append(Finding(UNKNOWN, AREA, label,
                           "no CA bundle found (distroless, scratch, or a static binary with its own roots?)",
                           "check the application itself; this tool cannot see inside compiled binaries"))

    for p in sorted(p for p, (k, _) in state.items() if k == "pkg"):
        nv = _NAMEVER_RE.match(_PKG_RE.search(p).group(1))
        name = norm(nv.group(1)) if nv else None
        if name in PYTHON_PACKAGES:
            ver = nv.group(2)
            level, msg = classify(name, "==" + ver, PYTHON_PACKAGES[name])
            fix = f"upgrade to {name}>={PYTHON_PACKAGES[name]} and rebuild the image" if level != OK else ""
            out.append(Finding(level, AREA, f"{label}: /{posixpath.dirname(posixpath.dirname(p))}", msg, fix))

    if cenv.get("PYTHON_VERSION") and parse_version(cenv["PYTHON_VERSION"]):
        out += judge_cpython(parse_version(cenv["PYTHON_VERSION"]), f"{label}: python", AREA)
    if cenv.get("NODE_VERSION"):
        out += judge_node(cenv["NODE_VERSION"], AREA, f"{label}: node {cenv['NODE_VERSION']}")
    go_files = [state[p][1] for p, (k, _) in sorted(state.items()) if k == "go"]
    go_text = _text(go_files[0]).splitlines()[0] if go_files and go_files[0] else (
        f"go{cenv['GOLANG_VERSION']}" if cenv.get("GOLANG_VERSION") else "")
    if go_text:
        out += judge_go(go_text, AREA, f"{label}: {go_text}")
    raw_java = None
    for p, (k, data) in sorted(state.items()):
        m = re.search(r'JAVA_VERSION="([^"]+)"', _text(data)) if k == "java" and data else None
        if m:
            raw_java = m.group(1)
            break
    if raw_java is None and cenv.get("JAVA_VERSION"):
        m = re.search(r"\d+(?:\.\d+)+", cenv["JAVA_VERSION"])
        raw_java = m.group(0) if m else None
    if raw_java:
        out += judge_java(raw_java, AREA, f"{label}: java {raw_java}")
    return out


# ---- entry points ----------------------------------------------------------------------------

def _docker_save(ref, path):
    if ref.startswith("-"):
        raise ImageError("not an existing file, and not a valid image name")
    exe = shutil.which("docker") or shutil.which("podman")
    if not exe:
        raise ImageError("not an existing file, and neither docker nor podman is on PATH")
    try:
        proc = subprocess.run([exe, "save", "-o", path, ref], capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ImageError(f"{os.path.basename(exe)} save failed: {exc}")
    if proc.returncode:
        lines = (proc.stderr or proc.stdout).strip().splitlines()
        raise ImageError(f"{os.path.basename(exe)} save failed: {lines[-1] if lines else 'unknown error'}")


_SCAN_ERRORS = (tarfile.TarError, OSError, EOFError, zlib.error, ValueError, KeyError, TypeError, AttributeError)


def check_archive(path, display=None):
    display = display or path
    try:
        with tarfile.open(path, "r:*") as tar:
            members = {_norm(m.name): m for m in tar.getmembers()}
            images, skipped = load_images(tar, members)
            out = [Finding(INFO, AREA, display, f"skipped {note}") for note in skipped]
            if not images:
                return out + [Finding(UNKNOWN, AREA, display, "no complete image found in the archive")]
            for label, config, layers in images:
                try:
                    out += judge_filesystem(label, config, replay(tar, members, layers))
                except ImageError as exc:
                    out.append(Finding(UNKNOWN, AREA, label, str(exc)))
                except _SCAN_ERRORS as exc:
                    out.append(Finding(UNKNOWN, AREA, label, f"could not read image layers: {exc}"))
            return out
    except ImageError as exc:
        return [Finding(UNKNOWN, AREA, display, str(exc))]
    except _SCAN_ERRORS as exc:
        return [Finding(UNKNOWN, AREA, display, f"could not read archive: {exc}")]


def check_image(ref):
    """`ref` is a path to a docker/OCI archive, or an image name that `docker save` can export."""
    if os.path.isfile(ref):
        return check_archive(ref)
    tmp = tempfile.mkdtemp(prefix="emudhra-image-")
    try:
        path = os.path.join(tmp, "image.tar")
        try:
            _docker_save(ref, path)
        except ImageError as exc:
            return [Finding(UNKNOWN, AREA, ref, str(exc))]
        return check_archive(path, ref)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_images(refs):
    return [f for ref in refs for f in check_image(ref)]
