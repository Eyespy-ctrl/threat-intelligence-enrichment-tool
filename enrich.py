# enrich.py
from modules.virustotal_lookup import lookup_virustotal
from modules.shodan_lookup import lookup_shodan
from modules.abuseipdb_lookup import lookup_abuseipdb
from modules.alienvault import lookup_alienvault
from database import db, Observable

def enrich_observable(value: str, obs_type: str):
    """
    Orchestrate provider calls, store provider results into DB as separate Observable rows.
    obs_type is 'ip' or 'domain' or 'url' etc.
    """
    providers = []

    # Run providers — each function returns a dict or None
    vt = lookup_virustotal(value, obs_type)
    if vt:
        providers.append(vt)

    sh = lookup_shodan(value, obs_type)
    if sh:
        providers.append(sh)

    ab = lookup_abuseipdb(value, obs_type)
    if ab:
        providers.append(ab)

    try:
        otx_data = lookup_alienvault(value, obs_type)
        if otx_data:
            providers.append(otx_data)
    except Exception as e:
        print("[AlienVault] error:", e)

    # Save provider results to database (one row per provider)
    for p in providers:
        # If provider returned an 'error' key, keep it in details
        provider_name = p.get("provider", "Unknown")
        country = p.get("country")
        score = p.get("score") if p.get("score") is not None else p.get("error", "N/A")
        details = p.get("details") or p.get("error") or ""

        rec = Observable(
            type=obs_type,
            value=value,
            provider=provider_name,
            country=country,
            score=str(score),
            details=str(details)
        )
        db.session.add(rec)

    # commit once
    db.session.commit()
    return providers
