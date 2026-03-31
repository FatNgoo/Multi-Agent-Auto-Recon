# tools/active/techstack_tool.py
import json
import re
import requests
from bs4 import BeautifulSoup
from crewai.tools import tool

_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


@tool("Technology Stack Analyzer")
def technology_stack_analyzer(url: str) -> str:
    """
    Phân tích sâu về technology stack của web application.
    Trích xuất: CMS, frameworks, JavaScript libraries, CDN, analytics, fonts.
    Input: URL (ví dụ: https://example.com)
    """
    from tools.active.http_helper import normalize_url, smart_request
    url = normalize_url(url)

    try:
        resp = smart_request(url, timeout=15, headers=_HEADERS)
        soup = BeautifulSoup(resp.text, "html.parser")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text

        tech = {
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""),
            "cms": None,
            "frameworks": [],
            "javascript_libraries": [],
            "cdn": [],
            "analytics": [],
            "fonts": [],
            "meta_tags": {},
            "form_count": 0,
            "external_links": [],
        }

        # Meta tags
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or ""
            content = meta.get("content", "")
            if name:
                tech["meta_tags"][name] = content[:200]

        # Scripts analysis
        scripts = [s.get("src", "") or s.string or "" for s in soup.find_all("script")]
        scripts = [str(s) for s in scripts if s]
        all_scripts = " ".join(scripts).lower()

        # CMS detection
        cms_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wp-json"],
            "Drupal": ["/sites/default/files/", "drupal.js", "drupal.min.js"],
            "Joomla": ["/components/com_", "joomla", "mootools"],
            "Magento": ["mage/", "Mage.Cookies", "varien"],
            "Shopify": ["cdn.shopify.com", "Shopify.theme"],
        }
        for cms, patterns in cms_patterns.items():
            if any(p in body.lower() for p in patterns):
                tech["cms"] = cms
                break

        # Framework detection
        framework_patterns = {
            "Laravel": ["laravel", "csrf-token", "XSRF-TOKEN"],
            "Django": ["csrfmiddlewaretoken", "__django"],
            "Rails": ["rails.js", "csrf-param"],
            "Spring": ["spring", "X-Application-Context"],
            "ASP.NET": ["__VIEWSTATE", "asp.net", "__EVENTVALIDATION"],
            "Next.js": ["__next", "_next/static"],
            "Nuxt.js": ["__nuxt", "_nuxt"],
        }
        for fw, patterns in framework_patterns.items():
            if any(p in body for p in patterns):
                tech["frameworks"].append(fw)

        # JS library detection from script tags
        js_patterns = {
            "jQuery": [r"jquery[.-](\d+\.\d+)", "jquery.min.js"],
            "React": ["react.min.js", "react-dom", "__REACT"],
            "Angular": ["angular.min.js", "ng-version"],
            "Vue.js": ["vue.min.js", "vue.js"],
            "Bootstrap": ["bootstrap.min.js", "bootstrap.bundle"],
            "Lodash": ["lodash.min.js"],
            "Moment.js": ["moment.min.js"],
            "Axios": ["axios.min.js"],
        }
        for lib, patterns in js_patterns.items():
            if any(p in all_scripts for p in patterns):
                tech["javascript_libraries"].append(lib)

        # CDN detection
        cdn_patterns = {
            "Cloudflare": ["cdnjs.cloudflare.com"],
            "jsDelivr": ["cdn.jsdelivr.net"],
            "unpkg": ["unpkg.com"],
            "Google CDN": ["ajax.googleapis.com"],
            "Bootstrap CDN": ["stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com"],
        }
        for cdn, patterns in cdn_patterns.items():
            if any(p in body for p in patterns):
                tech["cdn"].append(cdn)

        # Analytics
        analytics_patterns = {
            "Google Analytics": ["google-analytics.com", "gtag(", "UA-", "G-"],
            "Google Tag Manager": ["googletagmanager.com", "GTM-"],
            "Facebook Pixel": ["connect.facebook.net", "fbq("],
            "Hotjar": ["hotjar.com", "hjsv"],
            "Mixpanel": ["mixpanel.com"],
            "Segment": ["segment.com", "analytics.js"],
        }
        for analytics, patterns in analytics_patterns.items():
            if any(p in body for p in patterns):
                tech["analytics"].append(analytics)

        # Font sources
        if "fonts.googleapis.com" in body:
            tech["fonts"].append("Google Fonts")
        if "use.fontawesome.com" in body:
            tech["fonts"].append("Font Awesome")

        # Forms
        tech["form_count"] = len(soup.find_all("form"))

        # External links (just count by domain)
        ext_domains = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http") and url.split("/")[2] not in href:
                try:
                    ext_domain = href.split("/")[2]
                    ext_domains.add(ext_domain)
                except Exception:
                    pass
        tech["external_domains_count"] = len(ext_domains)

        return json.dumps(tech, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "url": url})
