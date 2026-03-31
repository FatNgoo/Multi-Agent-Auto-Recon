# tools/active/dirbust_tool.py
import json
import asyncio
import aiohttp
from crewai.tools import tool

WORDLIST_SMALL = [
    "admin", "login", "dashboard", "config", "backup", "api", "swagger",
    "graphql", "phpinfo.php", ".env", ".git", ".htaccess", "robots.txt",
    "sitemap.xml", "wp-admin", "wp-config.php", "wp-login.php",
    "administrator", "phpmyadmin", "cpanel", "webmail", "portal",
    "upload", "uploads", "static", "assets", "media", "images",
    "files", "download", "downloads", "public", "private", "secret",
    "test", "dev", "staging", "debug", "info", "server-status",
    "server-info", "console", "manager", "status", "health",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    ".git/HEAD", ".svn/entries", "web.config", "crossdomain.xml",
    "security.txt", ".well-known/security.txt", "readme.txt", "README.md",
    "CHANGELOG.txt", "license.txt", "backup.zip", "backup.tar.gz",
    "database.sql", "db.sql", ".DS_Store", "Thumbs.db",
]

WORDLIST_MEDIUM = WORDLIST_SMALL + [
    "old", "new", "temp", "tmp", "cache", "log", "logs", "error",
    "errors", "trace", "profile", "account", "accounts", "user",
    "users", "member", "members", "register", "signup", "forgot",
    "reset", "password", "passwd", "auth", "oauth", "sso", "saml",
    "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "v1", "v2", "v3", "version", "build", "dist", "src",
    "include", "includes", "lib", "libs", "vendor", "node_modules",
    "app", "application", "apps", "services", "service", "gateway",
    "proxy", "forward", "internal", "private", "secure", "ssl",
    "cgi-bin", "cgi-bin/env.cgi", "cgi-bin/printenv.pl",
    "phpMyAdmin", "adminer", "adminer.php", "dbadmin", "sqladmin",
    "mysql", "myadmin", "pma", "phpadmin", "mysqladmin",
    "wp-json", "xmlrpc.php", "wp-cron.php", "wp-trackback.php",
    "joomla", "drupal", "typo3", "contao", "concrete5",
    "struts", "grails", "rails", ".bundle", ".ruby-version",
    "composer.json", "package.json", "yarn.lock", "Gemfile",
    "requirements.txt", "Pipfile", "setup.py", "pom.xml",
    "settings.py", "settings.php", "configuration.php", "config.php",
    "database.php", "db.php", "connect.php", "connection.php",
    "credentials.json", "secrets.json", "env.json",
]

WORDLIST_LARGE = WORDLIST_MEDIUM + [
    f"page{i}" for i in range(1, 11)
] + [
    f"v{i}" for i in range(1, 6)
] + [
    "2015", "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023",
    "data", "dataset", "export", "import", "dump", "archive",
    "monitor", "monitoring", "metrics", "stats", "statistics",
    "report", "reports", "analytics", "insight", "insights",
]


def get_wordlist(size: str) -> list:
    if "large" in size.lower():
        return WORDLIST_LARGE
    elif "medium" in size.lower():
        return WORDLIST_MEDIUM
    return WORDLIST_SMALL


@tool("Directory Enumerator")
def directory_enumerator(input_json: str) -> str:
    """
    Liệt kê hidden directories và files bằng wordlist-based enumeration.
    Phát hiện: admin panels, config files, backup files, API endpoints.
    Input: JSON string {"url": "https://target.com", "wordlist_size": "small|medium|large"}
    """
    import json as _json
    try:
        params = _json.loads(input_json)
    except Exception:
        params = {"url": input_json.strip()}

    base_url = params.get("url", "")
    wordlist_size = params.get("wordlist_size", "small")

    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
    base_url = base_url.rstrip("/")

    wordlist = get_wordlist(wordlist_size)

    found = []
    redirects = []

    async def check_path(session: aiohttp.ClientSession, path: str):
        url = f"{base_url}/{path}"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    content_length = int(resp.headers.get("Content-Length", 0))
                    return {"type": "found", "path": f"/{path}", "status": 200,
                            "size": content_length, "note": "Accessible"}
                elif resp.status in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    return {"type": "redirect", "path": f"/{path}",
                            "status": resp.status, "destination": location}
                elif resp.status in (401, 403):
                    return {"type": "found", "path": f"/{path}", "status": resp.status,
                            "size": 0, "note": "Exists but access denied"}
        except Exception:
            pass
        return None

    async def run_all():
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            tasks = [check_path(session, p) for p in wordlist]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r]

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        all_results = loop.run_until_complete(run_all())
        loop.close()
    except Exception as e:
        return json.dumps({"error": str(e), "url": base_url})

    for r in all_results:
        if r["type"] == "found":
            found.append(r)
        elif r["type"] == "redirect":
            redirects.append(r)

    return json.dumps({
        "base_url": base_url,
        "wordlist_size": wordlist_size,
        "total_checked": len(wordlist),
        "found": found,
        "redirects": redirects[:20],
        "total_found": len(found),
    }, ensure_ascii=False, indent=2)
