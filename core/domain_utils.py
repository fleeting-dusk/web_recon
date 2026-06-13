from urllib.parse import urlparse


def extract_hostname(value):
    raw = str(value or "").strip()
    if not raw:
        return ""

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return host.strip().strip(".").lower()


def belongs_to_domain(hostname, root_domain):
    host = extract_hostname(hostname)
    root = extract_hostname(root_domain)
    return bool(host and root and (host == root or host.endswith(f".{root}")))
