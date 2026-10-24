"""Reference data for the October 2026 eMudhra intermediate-CA key compromise.

Source: https://emudhra.we-have-a-problem.com/ (impacted-intermediates.json,
roots.json and the "Who has patched?" tables), published by Dennis Jackson
(Mozilla) and contributors. Values were copied from that site on 2026-10-23.
Re-check the site before relying on this for anything important: the patched
version tables in particular change daily.
"""

SOURCE_URL = "https://emudhra.we-have-a-problem.com/"
DATA_AS_OF = "2026-10-23"

# (name, usage, SPKI sha256, cert sha256 issued by eMudhra root, cert sha256 cross-signed by Sectigo)
# The private keys behind all eight are integers < 256, so each key is public knowledge.
INTERMEDIATES = [
    ("EM DV TLS CA - G3B", "tls",
     "EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105",
     "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
     "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE"),
    ("EM OV TLS CA - G3B", "tls",
     "43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B",
     "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B",
     "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699"),
    ("EM EV TLS CA - G3B", "tls",
     "E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41",
     "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838",
     "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512"),
    ("EM DV TLS CA - G3C", "tls",
     "49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F",
     "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19",
     "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72"),
    ("EM OV TLS CA - G3C", "tls",
     "63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8",
     "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F",
     "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489"),
    ("EM EV TLS CA - G3C", "tls",
     "5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0",
     "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3",
     "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"),
    ("EM OV CS CA - G3B", "code-signing",
     "EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6",
     "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4",
     "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8"),
    ("EM OV CS CA - G3C", "code-signing",
     "92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30",
     "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1",
     "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"),
]

# Roots above the compromised intermediates: (name, role, cert sha256, SPKI sha256)
#   "distrust": being removed from browser root stores; certificates chaining here must be replaced.
#   "note":      a legitimate, still-trusted root that carries the Sectigo cross-signs.
ROOTS = [
    ("emSign Root TLS CA - G3", "distrust",
     "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D",
     "C619E4780ED8E0ABEDA24AD732567DE4383A7EA941338F6D1A7D1B49AC792FE9"),
    ("emSign Root CS CA - G3", "distrust",
     "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5",
     "0A6C2B2CA5B364207954171987AC9D2178561569D8205457E77CA90C32EDE282"),
    ("emSign ECC Root CA - G3", "distrust",
     "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B",
     "8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782"),
    ("AAA Certificate Services (Sectigo)", "note",
     "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4",
     "BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3"),
]

# Minimum safe versions of Python-ecosystem packages (PyPI names, normalised).
PYTHON_PACKAGES = {
    "certifi": "2026.10.19",
    "pip": "26.2.2",
    "uv": "0.13.4",
    "sigstore": "4.5.1",
    "pixi": "0.82.1",
}

# certifi 2026.10.18 already removed the weak roots (safe) but also dropped unaffected emSign roots;
# 2026.10.19 is the recommended release. Versions in [soft floor, recommended) are WARN, not FAIL.
SOFT_FLOORS = {"certifi": "2026.10.18"}

# Packages that pull in certifi even when it is not listed in a requirements file.
CERTIFI_USERS = {"requests", "httpx"}

# Patched CPython releases (these ship a fixed pip via ensurepip).
PATCHED_PYTHON = {(3, 15): (3, 15, 1), (3, 14): (3, 14, 9), (3, 13): (3, 13, 17)}
PATCHED_NODE = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
PATCHED_GO = {(1, 26): (1, 26, 10), (1, 27): (1, 27, 3)}
# Java: major -> (major, minor, security) from the vendor build numbers; the trailing
# ".0.2" style components differ between vendors, so equality is reported as "verify".
PATCHED_JAVA = {27: (27, 0, 1), 25: (25, 0, 5), 21: (21, 0, 13), 17: (17, 0, 21), 11: (11, 0, 33)}
PATCHED_JAVA8_UPDATE = 511

# Checker hosts run by the disclosure site; they deliberately serve the compromised chains.
TEST_HOSTS = [
    "dv-g3b-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com",
]

SPKI_TO_NAME = {spki: name for name, _u, spki, _c, _x in INTERMEDIATES}
CERT_TO_NAME = {}
for _n, _u, _s, _c1, _c2 in INTERMEDIATES:
    CERT_TO_NAME[_c1] = _n
    CERT_TO_NAME[_c2] = _n + " (Sectigo cross-sign)"
ROOT_BY_CERT = {c: (n, role) for n, role, c, _s in ROOTS}
ROOT_BY_SPKI = {s: (n, role) for n, role, _c, s in ROOTS}
