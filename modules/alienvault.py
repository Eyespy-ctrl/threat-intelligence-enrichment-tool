import os
from dotenv import load_dotenv
from OTXv2 import OTXv2, IndicatorTypes

load_dotenv()

OTX_KEY = os.getenv("ALIENVAULT_API_KEY")

otx = None
if not OTX_KEY:
    print("Warning: ALIENVAULT_API_KEY not found in .env - AlienVault lookups will fail")
else:
    try:
        otx = OTXv2(OTX_KEY)
    except Exception as e:
        print(f"Failed to initialize OTXv2: {e}")
        otx = None


def lookup_alienvault(observable: str, obs_type: str):
    """
    AlienVault OTX lookup - currently only supports IP addresses.
    """
    if obs_type.lower() != 'ip':
        return None

    if otx is None:
        return {"provider": "AlienVault", "error": "API key missing or initialization failed"}

    try:
        result = otx.get_indicator_details_full(IndicatorTypes.IPv4, observable)

        pulse_info = result.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_count = len(pulses)

        return {
            "provider": "AlienVault",
            "country": "N/A",  # OTX doesn't provide country here
            "score": str(pulse_count),
            "details": {
                "pulseCount": pulse_count
                # You can add more later, e.g.:
                # "first_pulse": pulses[0] if pulses else None
            }
        }
    except Exception as e:
        return {"provider": "AlienVault", "error": str(e)}
