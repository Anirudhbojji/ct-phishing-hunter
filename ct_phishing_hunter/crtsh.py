"""Query crt.sh (Certificate Transparency search) for recently issued certs
whose names mention a brand."""

from datetime import datetime, timedelta, timezone

import requests

CRTSH_URL = "https://crt.sh/"
REQUEST_TIMEOUT = 60
USER_AGENT = "ct-phishing-hunter (defensive brand monitoring)"


def recent_cert_domains(brand: str, days: int = 90) -> dict[str, str]:
    """Return {domain: latest issuance date} for certs mentioning the brand."""
    resp = requests.get(
        CRTSH_URL,
        params={"q": brand, "output": "json"},
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    domains: dict[str, str] = {}
    for entry in resp.json():
        seen = entry.get("entry_timestamp") or entry.get("not_before")
        if seen:
            try:
                when = datetime.fromisoformat(seen).replace(tzinfo=timezone.utc)
                if when < cutoff:
                    continue
            except ValueError:
                pass
        # name_value holds the CN plus SANs, newline-separated
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name:
                domains[name] = max(domains.get(name, ""), seen or "")
    return domains
