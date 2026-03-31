# tools/active/http_helper.py
"""Shared HTTP helper for active tools — smart protocol fallback."""
import requests

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


def smart_request(url: str, timeout: int = 15, **kwargs) -> requests.Response:
    """
    Try the given URL first. If it fails and uses HTTPS, fall back to HTTP
    (and vice versa). This handles targets that only support one protocol.
    """
    kwargs.setdefault("headers", _HEADERS)
    kwargs.setdefault("timeout", timeout)
    kwargs.setdefault("allow_redirects", True)
    kwargs.setdefault("verify", False)

    try:
        resp = requests.get(url, **kwargs)
        return resp
    except (requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.ConnectTimeout) as first_err:
        # Flip protocol and retry
        if url.startswith("https://"):
            alt_url = url.replace("https://", "http://", 1)
        elif url.startswith("http://"):
            alt_url = url.replace("http://", "https://", 1)
        else:
            raise first_err

        try:
            resp = requests.get(alt_url, **kwargs)
            return resp
        except Exception:
            raise first_err  # raise original if both fail


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme. Prefer http:// as many targets don't have SSL."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url
