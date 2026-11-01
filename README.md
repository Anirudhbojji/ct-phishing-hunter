# ct-phishing-hunter

Catch phishing and lookalike domains targeting your brand — by watching Certificate Transparency logs and DNS for the infrastructure attackers set up *before* the phishing email goes out.

Every TLS certificate issued anywhere on earth lands in public CT logs. When someone mints a cert for `acmec0rp.net` or `secure-yourbrand-login.com`, that's often the first observable step of a phishing campaign.

## Detection signals

| Kind | Example (brand: `acmecorp`) | Score |
|---|---|---|
| `homoglyph` | `acmec0rp.com`, `ternporal.com` (rn→m) | 95 |
| `typosquat` | `acmecrop.com` (edit distance ≤ 2) | 75–90 |
| `brand_token` | `acmecorp-login.com`, `secure-acmecorp.com` | 70 |
| `subdomain_spoof` | `acmecorp.evil-site.com` | 60 |

## Usage

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Explain how one domain scores
python -m ct_phishing_hunter score acmec0rp.com --brand acmecorp

# Search CT logs (crt.sh) for suspicious certs mentioning your brand
python -m ct_phishing_hunter sweep --brand acmecorp --allow acmecorp.com --allow acmecorp.net

# dnstwist-style: generate typo/homoglyph variants and find REGISTERED ones
python -m ct_phishing_hunter permutations acmecorp.net

# Live mode against a self-hosted certstream-compatible server
python -m ct_phishing_hunter watch --server wss://your-certstream:8080 --brand acmecorp
```

Example:

```
[ 95] homoglyph       acmec0rp.com  — 'acmec0rp' normalizes to 'acmecorp' (character substitution)
[ 90] typosquat       acmecrop.com  — 'acmecrop' is edit distance 2 from 'acmecorp'
[ 70] brand_token     acmecorp-login.com  — 'acmecorp-login' embeds brand 'acmecorp' with extra tokens
```

## Notes

- The sweep uses [crt.sh](https://crt.sh) (free, no key). The original public certstream server was discontinued — for live streaming, self-host e.g. [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go).
- The CT sweep finds names *containing* the brand; pure typosquats that drop characters are covered by the `permutations` scanner instead — use both.
- A registered lookalike or lookalike cert is a *lead*, not proof of malice — verify ownership (it may be a legit company with a similar name, a defensive registration, or a parked domain).
- Defensive tooling only: it reads public CT data and performs ordinary DNS lookups.

## Tests

```bash
pip install pytest && pytest tests/ -v
```
