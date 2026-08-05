import socket
import ssl
import csv
import requests
import whois
from datetime import datetime, timezone

INPUT_FILE = "domains.txt"
OUTPUT_FILE = "report.csv"

HEADERS = [
    "Domain",
    "Live",
    "HTTP Status",
    "IP Address",
    "Registrar",
    "Owner",
    "Creation Date",
    "Expiry Date",
    "SSL Expiry",
    "Trust Score",
    "Risk Status",
]

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "update", "account", "bank", "paypal",
    "microsoft", "google", "apple", "support", "office", "billing"
]

PRIVACY_KEYWORDS = [
    "privacy", "redacted", "whoisguard", "domain privacy", "protected",
    "contact privacy", "privacy service"
]


def parse_date(value):
    if not value:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if not value:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return value


def is_private_owner(text):
    if not text:
        return False
    text_l = str(text).lower()
    return any(k in text_l for k in PRIVACY_KEYWORDS)


def days_between(date_obj):
    if not isinstance(date_obj, datetime):
        return None
    now = datetime.now(timezone.utc)
    if date_obj.tzinfo is None:
        date_obj = date_obj.replace(tzinfo=timezone.utc)
    return (now - date_obj).days


def calculate_trust_score(domain, live, status, ssl_expiry, creation, registrar, owner):
    score = 100
    domain_l = domain.lower()

    # Live website signal
    if live == "Yes":
        score += 5
    else:
        score -= 10

    # HTTPS / SSL signal
    if ssl_expiry:
        try:
            expiry_dt = datetime.strptime(ssl_expiry, "%b %d %H:%M:%S %Y %Z")
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            if expiry_dt < datetime.now(timezone.utc):
                score -= 20
            else:
                remaining_days = (expiry_dt - datetime.now(timezone.utc)).days
                if remaining_days < 30:
                    score -= 10
        except:
            score -= 5
    else:
        score -= 10

    # WHOIS / registrar signal
    if not registrar:
        score -= 10

    if owner and is_private_owner(owner):
        score -= 5

    # Domain age
    if isinstance(creation, datetime):
        age_days = days_between(creation)
        if age_days is not None:
            if age_days < 180:
                score -= 15
            elif age_days < 365:
                score -= 8

    # Suspicious keyword heuristics
    if any(k in domain_l for k in SUSPICIOUS_KEYWORDS):
        score -= 10

    # HTTP status
    if status in [404, 500, 502, 503]:
        score -= 10

    score = max(0, min(100, score))

    if score >= 80:
        risk = "Safe"
    elif score >= 50:
        risk = "Suspicious"
    else:
        risk = "Risky"

    return score, risk


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    domains = [d.strip() for d in f if d.strip()]

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(HEADERS)

    for domain in domains:
        print(f"Scanning {domain}...")

        live = "No"
        status = ""
        ip = ""
        registrar = ""
        owner = ""
        creation = ""
        expiry = ""
        ssl_expiry = ""

        # Website check
        try:
            r = requests.get(
                "https://" + domain,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            live = "Yes"
            status = r.status_code
        except:
            try:
                r = requests.get(
                    "http://" + domain,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                live = "Yes"
                status = r.status_code
            except:
                pass

        # IP
        try:
            ip = socket.gethostbyname(domain)
        except:
            pass

        # SSL Expiry
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                ssl_expiry = cert.get("notAfter", "")
        except:
            pass

        # WHOIS
        try:
            w = whois.whois(domain)

            registrar = w.registrar if hasattr(w, "registrar") else ""

            if hasattr(w, "creation_date"):
                creation = parse_date(w.creation_date)

            if hasattr(w, "expiration_date"):
                expiry = parse_date(w.expiration_date)

            if hasattr(w, "org") and w.org:
                owner = w.org
            elif hasattr(w, "name") and w.name:
                owner = w.name

        except:
            pass

        trust_score, risk_status = calculate_trust_score(
            domain=domain,
            live=live,
            status=status,
            ssl_expiry=ssl_expiry,
            creation=creation,
            registrar=registrar,
            owner=owner
        )

        writer.writerow([
            domain,
            live,
            status,
            ip,
            registrar,
            owner,
            creation,
            expiry,
            ssl_expiry,
            trust_score,
            risk_status
        ])

print(f"\nReport saved as {OUTPUT_FILE}")
