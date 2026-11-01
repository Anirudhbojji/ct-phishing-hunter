"""Lookalike-domain scoring against protected brand names.

Signals, strongest first:
- homoglyph: the domain equals the brand once character tricks are undone
  (acmec0rp -> acmecorp, g00gle -> google, rn -> m)
- typosquat: edit distance 1-2 from the brand after normalization
- brand_token: the brand appears as a token with extra words bolted on
  (acmecorp-login.com, secure-acmecorp.com)
- subdomain_spoof: the brand is used as a subdomain of an unrelated domain
  (acmecorp.evil-site.com)
"""

from dataclasses import dataclass

HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i",
}
MULTI_CHAR_GLYPHS = {"rn": "m", "vv": "w", "cl": "d"}


@dataclass
class Match:
    domain: str
    brand: str
    kind: str  # homoglyph | typosquat | brand_token | subdomain_spoof
    score: int  # 0-100
    reason: str


def normalize(label: str) -> str:
    text = label.lower()
    for seq, repl in MULTI_CHAR_GLYPHS.items():
        text = text.replace(seq, repl)
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _labels(domain: str) -> list[str]:
    return domain.lower().rstrip(".").lstrip("*.").split(".")


def score_domain(domain: str, brand: str, allowlist: set[str] | None = None) -> Match | None:
    """Score one observed domain against one brand; None when unrelated/legit."""
    domain = domain.lower().rstrip(".").lstrip("*.")
    brand = brand.lower()
    if allowlist and (domain in allowlist or any(domain.endswith(f".{a}") for a in allowlist)):
        return None

    labels = _labels(domain)
    if len(labels) < 2:
        return None
    sld = labels[-2]
    subdomains = labels[:-2]

    if sld == brand:  # the brand's own registrable domain (allowlist handles legit ones)
        return None

    norm_sld = normalize(sld)
    if norm_sld == brand and sld != brand:
        return Match(domain, brand, "homoglyph", 95,
                     f"'{sld}' normalizes to '{brand}' (character substitution)")

    distance = levenshtein(norm_sld, brand)
    if 0 < distance <= 2 and len(brand) >= 5:
        return Match(domain, brand, "typosquat", 90 - 15 * (distance - 1),
                     f"'{sld}' is edit distance {distance} from '{brand}'")

    sld_tokens = norm_sld.replace("_", "-").split("-")
    if brand in sld_tokens and len(sld_tokens) > 1:
        return Match(domain, brand, "brand_token", 70,
                     f"'{sld}' embeds brand '{brand}' with extra tokens")

    if any(normalize(s) == brand for s in subdomains):
        return Match(domain, brand, "subdomain_spoof", 60,
                     f"brand '{brand}' used as subdomain of '{'.'.join(labels[-2:])}'")

    return None


def score_against_brands(domain: str, brands: list[str],
                         allowlist: set[str] | None = None) -> list[Match]:
    return [m for b in brands if (m := score_domain(domain, b, allowlist))]
