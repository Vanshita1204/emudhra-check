import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .data import DATA_AS_OF, SOURCE_URL, TEST_HOSTS
from .deps import discover, scan_file
from .domain import check_host
from .env import check_env
from .image import check_images
from .findings import FAIL, ORDER, OK, UNKNOWN, WARN

COLORS = {"FAIL": "31", "WARN": "33", "UNKNOWN": "35", "OK": "32", "INFO": "36"}


def _paint(text, level, on):
    return f"\033[{COLORS[level]}m{text}\033[0m" if on else text


def render(findings, color):
    lines, current = [], None
    for f in sorted(findings, key=lambda f: (f.area, ORDER[f.level])):
        if f.area != current:
            current = f.area
            lines.append(f"\n== {current} ==")
        lines.append(f"  {_paint(f'[{f.level:^7}]', f.level, color)} {f.subject}: {f.message}")
        if f.fix:
            lines.append(f"            -> {f.fix}")
    counts = {lvl: sum(1 for f in findings if f.level == lvl) for lvl in ORDER}
    summary = "  ".join(f"{k}={v}" for k, v in counts.items() if v)
    lines.append(f"\nSummary: {summary or 'nothing checked'}")
    if counts[FAIL]:
        lines.append("Result: AFFECTED - see FAIL items above.")
    elif counts[WARN] or counts[UNKNOWN]:
        lines.append("Result: no confirmed exposure, but some items could not be verified (WARN/UNKNOWN).")
    else:
        lines.append("Result: nothing affected found by these checks.")
    lines.append(f"Data: {SOURCE_URL} (copied {DATA_AS_OF}). Exposure to a stale trust list is not evidence of an attack.")
    return "\n".join(lines)


def build_parser():
    p = argparse.ArgumentParser(
        prog="emudhra-check",
        description="Check whether your dependencies, machine or servers are exposed to the Oct 2026 "
                    "eMudhra intermediate-CA key compromise.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # Shared flags work before or after the subcommand (SUPPRESS so one position never overwrites the other).
    common = argparse.ArgumentParser(add_help=False)
    for target in (p, common):
        target.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output")
        target.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
        target.add_argument("--strict", action="store_true", default=argparse.SUPPRESS,
                            help="exit 1 on WARN/UNKNOWN too, not just FAIL")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", parents=[common], help="check this machine and dependency files in a folder (default)")
    s.add_argument("path", nargs="?", default=".", help="folder to look for requirements*.txt / lockfiles")

    d = sub.add_parser("deps", parents=[common], help="check requirements.txt, pip freeze output, poetry.lock, uv.lock, Pipfile.lock")
    d.add_argument("files", nargs="+", help="files or folders")

    e = sub.add_parser("env", parents=[common], help="check pip/certifi, CA bundles, OS trust store and Node/Go/Java")
    e.add_argument("--python", action="append", metavar="PATH",
                   help="also check this interpreter (repeatable), e.g. a venv's bin/python")

    i = sub.add_parser("image", parents=[common],
                       help="check Docker/OCI image archives (or image names, exported with `docker save`)")
    i.add_argument("images", nargs="+", metavar="IMAGE",
                   help="path to a `docker save` / OCI tarball, or an image name docker/podman can export")

    h = sub.add_parser("domain", parents=[common], help="check the certificate chain a server presents")
    h.add_argument("hosts", nargs="*", help="host or host:port")
    h.add_argument("--self-test", action="store_true",
                   help="check the disclosure site's deliberately-vulnerable hosts (expect FAIL)")
    h.add_argument("--timeout", type=float, default=8.0)
    return p


def _deps(paths):
    findings = []
    for raw in paths:
        p = Path(raw)
        targets = discover(p) if p.is_dir() else [p]
        if p.is_dir() and not targets:
            from .findings import Finding, INFO
            findings.append(Finding(INFO, "deps", str(p), "no requirements*.txt or lockfiles found"))
        for t in targets:
            findings += scan_file(t)
    return findings


def project_pythons(folder):
    """Interpreters worth checking for a project folder: the active venv, a venv inside the folder, then PATH.

    The interpreter running this tool is skipped on purpose: under pipx/uvx it is the tool's own private
    environment, not the user's. It is only the fallback when nothing else is found.
    """
    found = []
    bases = [os.environ.get("VIRTUAL_ENV")] + [str(Path(folder) / n) for n in (".venv", "venv", "env")]
    for base in filter(None, bases):
        for rel in ("bin/python", "Scripts/python.exe"):
            cand = Path(base) / rel
            if cand.is_file():
                found.append(str(cand))
    for name in ("python3", "python"):
        cand = shutil.which(name)
        if cand:
            found.append(cand)
    unique = list(dict.fromkeys(os.path.abspath(c) for c in found))
    return unique or [sys.executable]


def main(argv=None):
    args = build_parser().parse_args(argv)
    cmd = args.cmd or "scan"
    if cmd == "scan":
        folder = getattr(args, "path", ".")
        findings = check_env(project_pythons(folder)) + _deps([folder])
    elif cmd == "deps":
        findings = _deps(args.files)
    elif cmd == "env":
        findings = check_env(args.python)
    elif cmd == "image":
        findings = check_images(args.images)
    elif cmd == "domain":
        hosts = list(args.hosts) + (TEST_HOSTS if args.self_test else [])
        if not hosts:
            print("give at least one host, or use --self-test", file=sys.stderr)
            return 2
        findings = [f for h in hosts for f in check_host(h, args.timeout)]
    else:  # pragma: no cover
        return 2

    if cmd in ("domain", "image") and findings and all(f.level == UNKNOWN for f in findings):
        print("\nNo host could be checked (network/DNS/proxy problem?)." if cmd == "domain"
              else "\nNo image could be read.", file=sys.stderr)
        rc_override = 2
    else:
        rc_override = None
    if getattr(args, "json", False):
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        color = sys.stdout.isatty() and not getattr(args, "no_color", False) and "NO_COLOR" not in os.environ
        print(render(findings, color))
    bad = {FAIL} | ({WARN, UNKNOWN} if getattr(args, "strict", False) else set())
    if rc_override is not None:
        return rc_override
    return 1 if any(f.level in bad for f in findings) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
