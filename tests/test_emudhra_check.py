import hashlib
import os
import shutil
import socket
import ssl
import threading
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from emudhra_check import cli, deps, domain, env, image, weakkey
from emudhra_check.data import CERT_TO_NAME, INTERMEDIATES, ROOTS, SPKI_TO_NAME
from emudhra_check.der import cert_fingerprint, pem_to_ders, spki_fingerprint
from emudhra_check.findings import FAIL, INFO, OK, UNKNOWN, WARN, cmp_versions, parse_version

# Public certificates copied from https://emudhra.we-have-a-problem.com/ (no private keys involved).
ECC_ROOT_PEM = """-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----
"""

DV_G3B_PEM = """-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQsw
CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1
NDA4WhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11
ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/J
hZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p
1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYi5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPO
Ibh1grvdULDCAjEAxZvLlxUavG69J6wnSjC8XBbqNIQsJ6CE2QdNOe84Ptxb6VG8
gt2TlfJbHii+KNvK
-----END CERTIFICATE-----
"""


def make_benign_cert():
    """Self-signed cert generated locally with openssl, or None if openssl is missing."""
    exe = shutil.which("openssl")
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as d:
        key, crt = Path(d, "k.pem"), Path(d, "c.pem")
        subprocess.run([exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", str(key), "-out", str(crt), "-subj", "/CN=benign.test", "-days", "2"],
                       check=True, capture_output=True)
        return crt.read_text(), exe


class DerAndData(unittest.TestCase):
    def test_ecc_root_hashes_match_published_values(self):
        der = pem_to_ders(ECC_ROOT_PEM)[0]
        name, role, cert_sha, spki_sha = next(r for r in ROOTS if r[0].startswith("emSign ECC"))
        self.assertEqual(cert_fingerprint(der), cert_sha)
        self.assertEqual(spki_fingerprint(der), spki_sha)

    def test_compromised_intermediate_matches_published_values(self):
        der = pem_to_ders(DV_G3B_PEM)[0]
        self.assertIn(cert_fingerprint(der), CERT_TO_NAME)
        self.assertEqual(SPKI_TO_NAME[spki_fingerprint(der)], "EM DV TLS CA - G3B")

    def test_spki_hash_agrees_with_openssl(self):
        made = make_benign_cert()
        if not made:
            self.skipTest("openssl not available")
        pem, exe = made
        pub = subprocess.run([exe, "x509", "-noout", "-pubkey"], input=pem.encode(), capture_output=True, check=True).stdout
        der_pub = subprocess.run([exe, "pkey", "-pubin", "-outform", "DER"], input=pub, capture_output=True, check=True).stdout
        self.assertEqual(spki_fingerprint(pem_to_ders(pem)[0]), hashlib.sha256(der_pub).hexdigest().upper())

    def test_data_is_complete(self):
        self.assertEqual(len(INTERMEDIATES), 8)
        self.assertEqual(len(CERT_TO_NAME), 16)
        for _n, _u, spki, c1, c2 in INTERMEDIATES:
            for h in (spki, c1, c2):
                self.assertRegex(h, r"^[0-9A-F]{64}$")

    def test_garbage_der_is_rejected_not_crashed(self):
        for blob in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x31\x00", b"\x30\x03\x30\x01"):
            with self.assertRaises(ValueError):
                spki_fingerprint(blob)


class ChainAnalysis(unittest.TestCase):
    def test_compromised_intermediate_fails(self):
        f = domain.analyze_chain(pem_to_ders(DV_G3B_PEM))
        self.assertTrue(any(x.level == FAIL and "EM DV TLS CA - G3B" in x.message for x in f))

    def test_distrusted_root_fails(self):
        f = domain.analyze_chain(pem_to_ders(ECC_ROOT_PEM))
        self.assertTrue(any(x.level == FAIL for x in f))

    def test_benign_chain_is_ok(self):
        made = make_benign_cert()
        if not made:
            self.skipTest("openssl not available")
        f = domain.analyze_chain(pem_to_ders(made[0]))
        self.assertTrue(any(x.level == OK for x in f))
        self.assertFalse(any(x.level == FAIL for x in f))

    def test_unreadable_cert_is_unknown(self):
        f = domain.analyze_chain([b"\x00\x01"])
        self.assertEqual(f[0].level, UNKNOWN)


class LiveFetch(unittest.TestCase):
    """End-to-end through a real TLS handshake with a local server (no network, no weak keys needed:
    the server presents a benign leaf and merely appends the public compromised intermediate cert)."""

    def serve(self, extra_chain_pem):
        exe = shutil.which("openssl")
        if not exe:
            self.skipTest("openssl not available")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key, crt = Path(tmp.name, "k.pem"), Path(tmp.name, "c.pem")
        subprocess.run([exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                        "-keyout", str(key), "-out", str(crt), "-subj", "/CN=localhost", "-days", "2"],
                       check=True, capture_output=True)
        chain = Path(tmp.name, "chain.pem")
        chain.write_text(crt.read_text() + extra_chain_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(chain), str(key))
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(10)

        def run():
            try:
                conn, _ = srv.accept()
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(5)
                    try:
                        tls.recv(1)
                    except (OSError, ssl.SSLError):
                        pass
            except (OSError, ssl.SSLError):
                pass
            finally:
                srv.close()

        threading.Thread(target=run, daemon=True).start()
        return srv.getsockname()[1]

    def check(self, port):
        with mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1"}):
            return domain.check_host(f"127.0.0.1:{port}", timeout=8)

    def test_benign_server_is_ok(self):
        f = self.check(self.serve(""))
        self.assertTrue(any(x.level == OK for x in f), f)

    def test_server_sending_compromised_intermediate_fails(self):
        f = self.check(self.serve(DV_G3B_PEM))
        self.assertTrue(any(x.level == FAIL and "EM DV TLS CA - G3B" in x.message for x in f), f)

    def test_unreachable_host_is_unknown(self):
        f = self.check(1)
        self.assertEqual(f[0].level, UNKNOWN)


class Bundles(unittest.TestCase):
    def test_bundle_with_distrusted_root_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "bundle.pem")
            p.write_text(ECC_ROOT_PEM)
            f = env._bundle_findings("test bundle", p)
            self.assertTrue(any(x.level == FAIL and "emSign ECC Root CA - G3" in x.message for x in f), f)

    def test_clean_bundle_is_ok(self):
        made = make_benign_cert()
        if not made:
            self.skipTest("openssl not available")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "bundle.pem")
            p.write_text(made[0])
            f = env._bundle_findings("test bundle", p)
            self.assertEqual([x.level for x in f], [OK])

    def test_unreadable_bundle_is_unknown(self):
        self.assertEqual(env._bundle_findings("x", "/nonexistent.pem")[0].level, UNKNOWN)


class Versions(unittest.TestCase):
    def test_parse_and_compare(self):
        self.assertEqual(parse_version("26.2.2rc1"), (26, 2, 2))
        self.assertEqual(parse_version("v22.23.4"), (22, 23, 4))
        self.assertIsNone(parse_version("abc"))
        self.assertEqual(cmp_versions((26, 2), (26, 2, 0)), 0)
        self.assertEqual(cmp_versions((26, 2, 1), (26, 2, 2)), -1)
        self.assertEqual(cmp_versions((2026, 10, 19), (2026, 10, 18)), 1)


class Deps(unittest.TestCase):
    def levels(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "requirements.txt")
            p.write_text(text)
            return {(f.level, f.message.split()[0]) for f in deps.scan_file(p)}

    def test_old_pins_fail_and_new_pins_pass(self):
        got = self.levels("certifi==2026.9.1\npip==26.2.2\nuv==0.13.3\nrequests==2.40.0\n")
        self.assertIn((FAIL, "certifi"), got)
        self.assertIn((OK, "pip"), got)
        self.assertIn((FAIL, "uv"), got)

    def test_unpinned_is_unknown_and_floor_is_ok(self):
        got = self.levels("certifi\nsigstore>=4.5.1\npixi>=0.80\n")
        self.assertIn((UNKNOWN, "certifi:"), got)
        self.assertIn((OK, "sigstore>=4.5.1:"), got)
        self.assertIn((WARN, "pixi>=0.80:"), got)

    def test_certifi_soft_floor_is_warn_not_fail(self):
        got = self.levels("certifi==2026.10.18\ncertifi==2026.10.18\n")
        self.assertIn((WARN, "certifi"), got)
        self.assertNotIn((FAIL, "certifi"), got)

    def test_markers_hashes_comments_and_extras(self):
        got = self.levels("# comment\ncertifi[extra]==2026.10.19 ; python_version>'3.8' \\\n    --hash=sha256:abc\n-r other.txt\n")
        self.assertIn((OK, "certifi"), got)

    def test_transitive_certifi_note(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "requirements.txt")
            p.write_text("requests==2.40.0\n")
            msgs = [f.message for f in deps.scan_file(p)]
            self.assertTrue(any("pulled in by requests" in m for m in msgs))

    def test_lockfiles(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "uv.lock").write_text('[[package]]\nname = "certifi"\nversion = "2026.1.1"\n')
            (Path(d) / "Pipfile.lock").write_text('{"default": {"pip": {"version": "==26.1.0"}}, "develop": {}}')
            f = deps.scan_file(Path(d) / "uv.lock") + deps.scan_file(Path(d) / "Pipfile.lock")
            self.assertEqual(sum(1 for x in f if x.level == FAIL), 2)

    def test_missing_file_is_unknown_not_crash(self):
        self.assertEqual(deps.scan_file("/nonexistent/requirements.txt")[0].level, UNKNOWN)



def _tar_bytes(files, gz=False):
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _write_archive(path, files):
    import io
    import tarfile
    with tarfile.open(path, "w") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))


def _docker_archive(path, layers, env_vars=()):
    import json
    cfg = json.dumps({"os": "linux", "architecture": "amd64", "config": {"Env": list(env_vars)}}).encode()
    files = {"cfg.json": cfg}
    names = []
    for i, layer in enumerate(layers):
        names.append(f"l{i}/layer.tar")
        files[names[-1]] = _tar_bytes(layer)
    files["manifest.json"] = json.dumps([{"Config": "cfg.json", "RepoTags": ["test:1"], "Layers": names}]).encode()
    _write_archive(path, files)


def _oci_archive(path, layers, env_vars=()):
    import json
    blobs = {}

    def put(data):
        d = hashlib.sha256(data).hexdigest()
        blobs[f"blobs/sha256/{d}"] = data
        return "sha256:" + d
    cfg = put(json.dumps({"os": "linux", "architecture": "arm64", "config": {"Env": list(env_vars)}}).encode())
    ldesc = [{"digest": put(_tar_bytes(layer, gz=True))} for layer in layers]
    manifest = put(json.dumps({"config": {"digest": cfg}, "layers": ldesc}).encode())
    index = {"manifests": [{"digest": manifest, "annotations": {"org.opencontainers.image.ref.name": "oci:1"},
                            "platform": {"os": "linux", "architecture": "arm64"}}]}
    _write_archive(path, {"index.json": json.dumps(index).encode(), **blobs})



class WeakKeys(unittest.TestCase):
    def test_published_compromised_intermediate_has_a_tiny_key(self):
        k = weakkey.tiny_private_key(pem_to_ders(DV_G3B_PEM)[0])
        self.assertIsNotNone(k)
        self.assertLess(k, 256)  # the disclosure says every compromised key is below 256

    def test_normal_ec_root_is_not_flagged(self):
        self.assertIsNone(weakkey.tiny_private_key(pem_to_ders(ECC_ROOT_PEM)[0]))

    def test_non_ec_and_garbage_are_ignored(self):
        self.assertIsNone(weakkey.tiny_private_key(b"\x30\x03\x02\x01\x00"))
        self.assertIsNone(weakkey.parse_ec_spki(b"junk"))

    def test_curve_constants_are_consistent(self):
        def add(P, Q, p):
            if P is None or Q is None:
                return P or Q
            if P[0] == Q[0]:
                if (P[1] + Q[1]) % p == 0:
                    return None
                lam = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
            else:
                lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
            x = (lam * lam - P[0] - Q[0]) % p
            return x, (lam * (P[0] - x) - P[1]) % p
        for c in weakkey.CURVES.values():
            self.assertEqual((c.gy ** 2 - (c.gx ** 3 - 3 * c.gx + c.b)) % c.p, 0, c.name)
            acc, pt = None, (c.gx, c.gy)
            k = c.n
            while k:
                if k & 1:
                    acc = add(acc, pt, c.p)
                pt = add(pt, pt, c.p)
                k >>= 1
            self.assertIsNone(acc, c.name)  # n*G is the point at infinity

    def test_unlisted_tiny_key_in_a_served_chain_fails(self):
        der = pem_to_ders(DV_G3B_PEM)[0]
        with mock.patch.object(domain, "SPKI_TO_NAME", {}), mock.patch.object(domain, "CERT_TO_NAME", {}), \
                mock.patch.object(domain, "_COMPROMISED_NAMES", []), mock.patch.object(domain, "_DISTRUST_NAMES", {}):
            f = domain.analyze_chain([der], "x")
        self.assertEqual(f[0].level, FAIL)
        self.assertIn("not on the published list", f[0].message)

    def test_tiny_key_ca_in_a_bundle_fails(self):
        f = env.judge_bundle("b", "/x.pem", env.scan_bundle_text(DV_G3B_PEM))
        self.assertEqual(f[0].level, FAIL)
        self.assertIn("tiny integer", f[0].message)
        clean = env.judge_bundle("b", "/x.pem", env.scan_bundle_text("# empty"))
        self.assertEqual(clean[0].level, OK)


class Images(unittest.TestCase):
    BAD = {"etc/ssl/certs/ca-certificates.crt": ECC_ROOT_PEM.encode()}

    def check(self, builder, layers, env_vars=()):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "img.tar")
            builder(p, layers, env_vars)
            return image.check_image(p)

    def levels(self, findings):
        return {f.level for f in findings}

    def test_docker_archive_with_distrusted_root_fails(self):
        f = self.check(_docker_archive, [self.BAD])
        self.assertIn(FAIL, self.levels(f))
        self.assertTrue(any("emSign ECC Root CA - G3" in x.message for x in f))

    def test_oci_archive_with_gzip_layers_fails(self):
        f = self.check(_oci_archive, [self.BAD])
        self.assertIn(FAIL, self.levels(f))
        self.assertTrue(any("oci:1 (linux/arm64)" in x.subject for x in f))

    def test_whiteout_in_later_layer_removes_the_bundle(self):
        f = self.check(_docker_archive, [self.BAD, {"etc/ssl/certs/.wh.ca-certificates.crt": b""}])
        self.assertNotIn(FAIL, self.levels(f))
        self.assertIn(UNKNOWN, self.levels(f))  # no bundle left: reported, never "safe"

    def test_overwrite_in_later_layer_replaces_the_bundle(self):
        f = self.check(_docker_archive, [self.BAD, {"etc/ssl/certs/ca-certificates.crt": b"# empty\n"}])
        self.assertNotIn(FAIL, self.levels(f))
        self.assertIn(OK, self.levels(f))

    def test_opaque_dir_hides_lower_layer(self):
        f = self.check(_docker_archive, [self.BAD, {"etc/ssl/certs/.wh..wh..opq": b""}])
        self.assertNotIn(FAIL, self.levels(f))

    def test_old_pip_and_certifi_in_site_packages(self):
        sp = "usr/local/lib/python3.13/site-packages/"
        f = self.check(_docker_archive, [{
            sp + "pip-25.0.dist-info/METADATA": b"Name: pip\n",
            sp + "certifi-2026.10.19.dist-info/METADATA": b"Name: certifi\n",
            "etc/ssl/certs/ca-certificates.crt": b"",
        }])
        pip = [x for x in f if x.area == "image" and x.message.startswith("pip ")]
        self.assertEqual([x.level for x in pip], [FAIL])
        self.assertTrue(any(x.level == OK and x.message.startswith("certifi ") for x in f))

    def test_runtime_versions_from_image_config_and_files(self):
        f = self.check(_docker_archive, [{
            "etc/ssl/certs/ca-certificates.crt": b"",
            "usr/local/go/VERSION": b"go1.26.1\ntime 2026-01-01\n",
            "opt/java/openjdk/release": b'JAVA_VERSION="17.0.2"\n',
        }], ["PYTHON_VERSION=3.13.1", "NODE_VERSION=22.1.0"])
        text = " | ".join(f"{x.level} {x.subject}" for x in f)
        for needle in ("FAIL test:1: go1.26.1", "FAIL test:1: java 17.0.2", "FAIL test:1: node 22.1.0",
                       "WARN test:1: python"):
            self.assertIn(needle, text)

    def test_bad_archives_are_unknown_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            junk = os.path.join(d, "junk.tar")
            Path(junk).write_bytes(b"not a tar at all")
            self.assertEqual([x.level for x in image.check_image(junk)], [UNKNOWN])
            empty = os.path.join(d, "empty.tar")
            _write_archive(empty, {"hello.txt": b"hi"})
            self.assertEqual([x.level for x in image.check_image(empty)], [UNKNOWN])
            broken = os.path.join(d, "broken.tar")
            _write_archive(broken, {"manifest.json": b'[{"Config": "c.json", "Layers": ["x/layer.tar"]}]',
                                    "c.json": b"{}"})
            self.assertEqual([x.level for x in image.check_image(broken)], [UNKNOWN])

    def test_zstd_layer_is_unknown(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "z.tar")
            _write_archive(p, {"manifest.json": json.dumps([{"Config": "c.json", "Layers": ["l.tar"]}]).encode(),
                               "c.json": b"{}", "l.tar": b"\x28\xb5\x2f\xfd" + b"\0" * 32})
            f = image.check_image(p)
            self.assertEqual([x.level for x in f], [UNKNOWN])
            self.assertIn("zstd", f[0].message)

    def test_image_name_without_engine_is_unknown(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual([x.level for x in image.check_image("no-such/image:tag")], [UNKNOWN])
        self.assertEqual([x.level for x in image.check_image("--evil")], [UNKNOWN])

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.tar")
            _docker_archive(bad, [self.BAD], ())
            junk = os.path.join(d, "junk.tar")
            Path(junk).write_bytes(b"x")
            with mock.patch("sys.stdout"):
                self.assertEqual(cli.main(["image", bad]), 1)
                self.assertEqual(cli.main(["image", junk]), 2)
                self.assertEqual(cli.main(["image", "--json", bad]), 1)


if __name__ == "__main__":
    unittest.main()
