from dataclasses import asdict, dataclass

FAIL, WARN, UNKNOWN, OK, INFO = "FAIL", "WARN", "UNKNOWN", "OK", "INFO"
ORDER = {FAIL: 0, WARN: 1, UNKNOWN: 2, OK: 3, INFO: 4}


@dataclass
class Finding:
    level: str
    area: str       # deps | env | domain | image
    subject: str    # what was checked
    message: str    # what was found
    fix: str = ""   # what to do

    def to_dict(self):
        return asdict(self)


def parse_version(text):
    """Leading numeric release tuple: '26.2.2rc1' -> (26, 2, 2). Pre-releases count as the release."""
    import re
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", text or "")
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def cmp_versions(a, b):
    """Compare version tuples, padding with zeros. Returns -1, 0, 1."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)
