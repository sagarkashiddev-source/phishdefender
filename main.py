from fastapi import FastAPI, Request
from pydantic import BaseModel
import tldextract, random

app = FastAPI(title="PhishDefender")

class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"message": "PhishDefender API is live!"}

@app.post("/scan/url")
def scan_url(request: URLRequest):
    url = request.url
    domain = tldextract.extract(url).domain
    phishing_keywords = ["verify", "login", "secure", "update", "account", "password", "bank"]
    score = sum(k in url.lower() for k in phishing_keywords) / len(phishing_keywords)
    label = "phishing" if score > 0.4 else "safe"
    return {"url": url, "domain": domain, "score": round(score, 2), "label": label}
