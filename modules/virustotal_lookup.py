# modules/virustotal_lookup.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")
VT_HEADERS = {"x-apikey": VT_KEY} if VT_KEY else {}

def lookup_virustotal(observable: str, obs_type: str):
    """
    VirusTotal v3 lookup for ip or domain.
    Returns dict with keys: provider, country, score, details OR {'provider': 'VirusTotal', 'error': '...'}
    """
    if not VT_KEY:
        return None

    endpoint = "ip_addresses" if obs_type == "ip" else "domains"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{observable}"
    try:
        r = requests.get(url, headers=VT_HEADERS, timeout=15)
        r.raise_for_status()
        js = r.json()
        attrs = js.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        reputation = attrs.get("reputation")

        # Prefer explicit reputation; fallback to malicious count
        score = reputation if reputation is not None else stats.get("malicious", 0)

        details = {
            "reputation": reputation,
            "last_analysis_stats": stats,
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

        return {
            "provider": "VirusTotal",
            "country": attrs.get("country"),
            "score": str(score),
            "details": details
        }
    except requests.HTTPError as e:
        # include status code / message
        code = e.response.status_code if e.response is not None else "HTTP"
        return {"provider": "VirusTotal", "error": f"HTTP {code}: {e}"}
    except Exception as e:
        return {"provider": "VirusTotal", "error": str(e)}
