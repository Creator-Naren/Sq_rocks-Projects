import re
from urllib.parse import urlparse

KEYWORDS = ["login", "verify", "secure", "update", "account", "bank", "paypal"]
SUSPICIOUS_TLDS = (".zip", ".mov", ".top", ".xyz", ".tk", ".click", ".link")


def phish_score(url):
    p = urlparse(url)
    host = p.netloc.lower()
    score = 0

    if not url.startswith("https"):
        score += 30

    for kw in KEYWORDS:
        if kw in host:
            score += 20

    if host.count(".") > 3:
        score += 25

    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
        score += 40

    if "@" in url:
        score += 25

    if host.startswith("xn--") or ".xn--" in host:
        score += 30

    if host.endswith(SUSPICIOUS_TLDS):
        score += 15

    return min(score, 100)


def verdict(score):
    if score >= 70:
        return "HIGH RISK"
    if score >= 40:
        return "SUSPICIOUS"
    return "LIKELY SAFE"


if __name__ == "__main__":
    urls = [
        "https://paypal-login.evil.com/verify",
        "https://github.com",
        "http://192.168.1.1/login",
        "https://paypal.com.secure-update.top/account",
        "https://www.google.com/search?q=login",
        "http://xn--pypal-4ve.com/secure",
        "https://user@bank.verify.evil.co/update",
    ]
    for u in urls:
        s = phish_score(u)
        print(f"{u} -> Risk: {s}% ({verdict(s)})")
