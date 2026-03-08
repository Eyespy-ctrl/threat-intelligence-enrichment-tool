# modules/abuseipdb_lookup.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

def lookup_abuseipdb(observable: str, obs_type: str):
    """
    AbuseIPDB lookup (IP only). Returns dict or None.
    """
    if not ABUSE_KEY or obs_type != "ip":
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params = {"ipAddress": observable, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
        r.raise_for_status()
        j = r.json()
        data = j.get("data", {}) or {}
        score = data.get("abuseConfidenceScore")
        details = {
            "totalReports": data.get("totalReports"),
            "usageType": data.get("usageType"),
            "lastReportedAt": data.get("lastReportedAt")
        }
        return {
            "provider": "AbuseIPDB",
            "country": data.get("countryCode"),
            "score": str(score) if score is not None else None,
            "details": details
        }
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "HTTP"
        return {"provider": "AbuseIPDB", "error": f"HTTP {code}: {e}"}
    except Exception as e:
        return {"provider": "AbuseIPDB", "error": str(e)}
