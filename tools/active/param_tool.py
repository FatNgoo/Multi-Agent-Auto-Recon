# tools/active/param_tool.py
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from crewai.tools import tool

COMMON_PARAMS = [
    "id", "user", "uid", "username", "page", "search", "q", "query",
    "s", "keyword", "keywords", "term", "cat", "category", "type",
    "action", "cmd", "command", "exec", "execute", "file", "filename",
    "path", "dir", "directory", "url", "link", "href", "src", "source",
    "dest", "destination", "redirect", "redir", "return", "returnurl",
    "next", "back", "goto", "target", "ref", "referrer", "origin",
    "token", "key", "apikey", "api_key", "access_token", "auth_token",
    "session", "sess", "sid", "sessionid", "jsessionid",
    "lang", "language", "locale", "region", "country",
    "format", "output", "type", "view", "template",
    "orderby", "sort", "order", "sortby", "asc", "desc",
    "limit", "offset", "start", "end", "from", "to",
    "filter", "status", "state", "mode", "tab",
    "email", "mail", "phone", "name", "first", "last",
    "code", "callback", "debug", "verbose", "trace",
    "include", "exclude", "fields", "select",
    "ajax", "xhr", "json", "xml", "response",
]

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}


@tool("Parameter Discoverer")
def param_discoverer(url: str) -> str:
    """
    Phát hiện hidden GET parameters trên web pages.
    Tìm các parameters không được document nhưng được server xử lý.
    Input: URL (ví dụ: https://example.com/page)
    """
    from tools.active.http_helper import normalize_url, smart_request
    url = normalize_url(url)

    try:
        # Get baseline response
        baseline = smart_request(url, timeout=15, headers=_HEADERS)
        baseline_len = len(baseline.text)
        baseline_code = baseline.status_code

        discovered = []

        def check_param(param):
            test_url = f"{url}?{param}=test_value_12345"
            try:
                resp = requests.get(test_url, headers=_HEADERS, timeout=5, verify=False)
                # Different response = param exists
                if (resp.status_code != baseline_code or
                        abs(len(resp.text) - baseline_len) > 50):
                    return {
                        "param": param,
                        "url": test_url,
                        "baseline_code": baseline_code,
                        "response_code": resp.status_code,
                        "size_diff": len(resp.text) - baseline_len,
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(check_param, p): p for p in COMMON_PARAMS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)

        return json.dumps({
            "url": url,
            "params_tested": len(COMMON_PARAMS),
            "params_found": len(discovered),
            "discovered_params": discovered,
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "url": url})
