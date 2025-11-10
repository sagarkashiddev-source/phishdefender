from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import tldextract
import re

# -----------------------------------------------------------
# 🎯 PhishDefender — Real-Time Phishing URL Detection API
# -----------------------------------------------------------

app = FastAPI(
    title="PhishDefender",
    description="Detect phishing URLs in real time using heuristic analysis",
    version="2.0"
)

# -----------------------------------------------------------
# 🧩 Data Model
# -----------------------------------------------------------
class URLRequest(BaseModel):
    url: str


# -----------------------------------------------------------
# ⚙️ Utility Functions
# -----------------------------------------------------------
def calculate_phishing_score(url: str) -> dict:
    url = url.lower()

    # 🧠 1. Keyword-based heuristic
    phishing_keywords = [
        "login", "verify", "update", "secure", "account", "bank", "confirm",
        "reset", "password", "signin", "unlock", "verification", "support",
        "billing", "authentication", "validate", "webmail", "alert"
    ]

    keyword_hits = [k for k in phishing_keywords if k in url]
    keyword_score = len(keyword_hits) / len(phishing_keywords)

    # 🧬 2. URL structure analysis (too many dots, hyphens, or suspicious TLDs)
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}" if domain_info.suffix else domain_info.domain
    suspicious_tlds = ["tk", "ml", "ga", "cf", "gq", "xyz", "top"]
    tld_score = 0.2 if domain_info.suffix in suspicious_tlds else 0

    # 🕵️‍♂️ 3. Length-based heuristic (very long URLs are risky)
    length_score = 0.1 if len(url) > 75 else 0

    # ⚙️ 4. Count of special characters
    special_chars = len(re.findall(r"[-_@=]", url))
    special_score = min(special_chars / 10, 0.2)  # cap at 0.2

    # 🧮 Combine all heuristics
    total_score = round(min(keyword_score + tld_score + length_score + special_score, 1.0), 2)
    label = "phishing" if total_score >= 0.2 else "safe"

    # 💬 Reason summary
    reasons = []
    if keyword_hits:
        reasons.append(f"Contains suspicious keywords: {', '.join(keyword_hits)}")
    if tld_score > 0:
        reasons.append(f"Suspicious TLD: .{domain_info.suffix}")
    if length_score > 0:
        reasons.append("URL is unusually long")
    if special_score > 0.15:
        reasons.append("Contains many special characters")

    if not reasons:
        reasons.append("No phishing indicators detected")

    return {
        "url": url,
        "domain": domain,
        "score": total_score,
        "label": label,
        "reasons": reasons
    }


# -----------------------------------------------------------
# 🔍 Main API Endpoint
# -----------------------------------------------------------
@app.post("/scan/url")
def scan_url(request: URLRequest):
    return calculate_phishing_score(request.url)


# -----------------------------------------------------------
# 🌐 Frontend Integration
# -----------------------------------------------------------
app.mount("/", StaticFiles(directory="static", html=True), name="static")
