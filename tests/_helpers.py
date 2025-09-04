from urllib.parse import urlsplit


def ensure_host_header(prepared):
    """Ensure 'host' header exists (lower-case) before signing a PreparedRequest.

    Requests does not always add Host until send-time; since we sign prior to sending,
    we inject it ourselves to keep signature covered components consistent.
    """
    if "host" not in prepared.headers:
        prepared.headers["host"] = urlsplit(prepared.url).netloc
    return prepared
