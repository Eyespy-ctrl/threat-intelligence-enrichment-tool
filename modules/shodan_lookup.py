# modules/shodan_lookup.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()
SHODAN_KEY = os.getenv("SHODAN_API_KEY")

def lookup_shodan(observable: str, obs_type: str):
    """
    Shodan host lookup (IP only).
    Returns dict or None (if key missing or not IP).
    """
    if not SHODAN_KEY or obs_type != "ip":
        return None

    url = f"https://api.shodan.io/shodan/host/{observable}"
    params = {"key": SHODAN_KEY}
    try:
        r = requests.get(url, params=params, timeout=15)
        r.raise_for_status()
        j = r.json()
        ports = j.get("ports") or []
        vulns = j.get("vulns") or []
        score = f"{len(ports)} open ports" if ports else "0 open ports"
        details = {
            "org": j.get("org"),
            "isp": j.get("isp"),
            "country": j.get("country_name"),
            "ports": ports,
            "vulns": vulns,
            "data_summary": {k: j.get(k) for k in ("hostnames","os","tags") if j.get(k)}
        }
        return {
            "provider": "Shodan",
            "country": j.get("country_name"),
            "score": score,
            "details": details
        }
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "HTTP"
        return {"provider": "Shodan", "error": f"HTTP {code}: {e}"}
    except Exception as e:
        return {"provider": "Shodan", "error": str(e)}
