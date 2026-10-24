# emudhra-check

A command-line checker for the October 2026 eMudhra intermediate-CA key compromise.
Eight eMudhra intermediate CAs (six TLS, two code signing) had private keys that were tiny
integers, so anyone could recover them. Browsers blocked the certificates within days, but
software that bundles its own CA list or skips revocation checks can still trust them.

This tool answers one question: **is anything I run still exposed to a stale trust list?**
It does not detect attacks, and exposure is not evidence that anyone was attacked.

Pure standard library. Python 3.10+ (3.11+ for `poetry.lock` / `uv.lock`).

## Install and run in your project

Nothing else is installed (no dependencies).

```
cd your-project
uvx --from git+https://github.com/Vanshita1204/emudhra-check.git emudhra-check          # no install; or: pipx run --spec git+https://github.com/Vanshita1204/emudhra-check.git emudhra-check
# or install it once:
pipx install git+https://github.com/Vanshita1204/emudhra-check.git   &&   emudhra-check
```

With no arguments it checks, for the current folder: `requirements*.txt` and lockfiles, the active venv
(`$VIRTUAL_ENV`), a `.venv`/`venv`/`env` folder here, the `python3` on your PATH, the system CA store, and
Node/Go/Java. It deliberately does not inspect its own pipx/uvx environment. Point it elsewhere with
`emudhra-check scan path/to/project`, and check built images with `emudhra-check image myapp:latest`.

## Use

```
python -m emudhra_check                      # machine check + dependency files in this folder
python -m emudhra_check deps requirements.txt poetry.lock uv.lock Pipfile.lock
python -m emudhra_check env                  # this interpreter, CA bundles, OS store, Node/Go/Java
python -m emudhra_check env --python venv/bin/python --python /usr/bin/python3
python -m emudhra_check image myapp:latest  # Docker image (exported with `docker save`; podman also works)
python -m emudhra_check image image.tar     # `docker save` or OCI image archive, no Docker needed
python -m emudhra_check domain example.com api.example.com:8443
python -m emudhra_check domain --self-test   # the disclosure site's deliberately vulnerable hosts: expect FAIL
```

Add `--json` for machine-readable output and `--strict` to fail CI on WARN/UNKNOWN too.
Exit codes: `0` nothing confirmed, `1` something affected, `2` nothing could be checked.

## What each check does

| Command | Checks |
| --- | --- |
| `deps` | certifi, pip, uv, sigstore, pixi versions against the fixed releases. Unpinned packages are reported as UNKNOWN, never as safe. |
| `env` | Installed pip/certifi versions, then the actual CA bundle files (pip's vendored bundle, certifi, system store, `PIP_CERT`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`...) for the distrusted roots by SHA-256, plus Python, Node, Go and Java versions. |
| `image` | Replays the image's layers in memory (nothing is run or written to disk) and inspects the final filesystem: CA bundles (`ca-certificates.crt`, `cacert.pem` incl. pip's and certifi's, individual files under `/usr/share/ca-certificates`) by SHA-256, pip/certifi/uv/sigstore/pixi versions from `site-packages`, and Python/Node/Go/Java versions from the image config, Go's `VERSION` and Java's `release` file. |
| `domain` | Fetches the chain a server sends (honours `HTTPS_PROXY`) and matches every certificate's SPKI hash, certificate hash and issuer name against the eight compromised keys and the distrusted emSign roots. |

## Unlisted weak keys

Besides matching the eight published keys, `domain`, `env` and `image` test every EC certificate they see
(P-256, P-384, P-521) for the same flaw directly: if its public key equals `k*G` for any `k <= 4096`, the private
key is recoverable and it is reported as FAIL even if it is not on the published list. RSA keys and larger
`k` are not tested. This does not search for other kinds of weak keys.

## Limits (read these)

- A dependency file only shows what it lists. `pip` itself is rarely listed, so run `env` per interpreter, venv and container image.
- `image` reads Docker (`manifest.json`) and OCI (`index.json`) archives with gzip or uncompressed layers. zstd layers are reported as UNKNOWN (the standard library cannot decompress them). Multi-platform archives are checked per platform whose blobs are present. Image names are exported with `docker save`/`podman save`, which needs a running daemon.
- `image` only looks at well-known CA bundle names and paths, installed Python packages, and runtime versions. A CA bundle copied under another name, Java's binary `cacerts` keystore, OS package versions, and roots compiled into a binary are not inspected. An image with no CA bundle is reported UNKNOWN, never OK.
- Go binaries must be rebuilt with a patched toolchain; this tool cannot see inside a compiled binary.
- `domain` inspects the chain the server sends. A server that omits its intermediates is not visible.
- The Java check is best effort: vendors use different build suffixes, so an equal version is reported as "verify".
- Reference data was copied from https://emudhra.we-have-a-problem.com/ on 2026-10-23. Patched-version tables change daily: edit `src/emudhra_check/data.py` or re-check the site.
- The live `domain` path was tested end to end against a local TLS server, not against the real
  disclosure hosts (the build sandbox blocked them). Run `domain --self-test` once on your own machine.
- Scope is the October 2026 incident only. eMudhra's Indian DSC and eSign services are stated by the company to be unaffected.

## Tests

```
python -m unittest discover -s tests -v
```
