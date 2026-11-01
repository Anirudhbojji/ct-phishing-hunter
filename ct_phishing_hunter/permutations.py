"""dnstwist-style permutation scanning.

Generate plausible typo/homoglyph variants of a protected domain, then check
which ones actually resolve in DNS — a registered lookalike is the strongest
early signal of an impending phishing campaign.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

KEYBOARD_NEIGHBORS = {
    "a": "qs", "b": "vn", "c": "xv", "d": "sf", "e": "wr", "f": "dg", "g": "fh",
    "h": "gj", "i": "uo", "j": "hk", "k": "jl", "l": "k", "m": "n", "n": "bm",
    "o": "ip", "p": "o", "q": "w", "r": "et", "s": "ad", "t": "ry", "u": "yi",
    "v": "cb", "w": "qe", "x": "zc", "y": "tu", "z": "x",
}
GLYPH_SWAPS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv"}


def generate_permutations(domain: str) -> set[str]:
    """Typo/homoglyph variants of a registrable domain (sld.tld)."""
    sld, _, tld = domain.lower().partition(".")
    variants: set[str] = set()

    for i in range(len(sld)):
        variants.add(sld[:i] + sld[i + 1:])                      # omission
        variants.add(sld[:i] + sld[i] + sld[i:])                 # repetition
        if i < len(sld) - 1:                                     # transposition
            variants.add(sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:])
        for neighbor in KEYBOARD_NEIGHBORS.get(sld[i], ""):      # fat-finger
            variants.add(sld[:i] + neighbor + sld[i + 1:])
        if sld[i] in GLYPH_SWAPS:                                # homoglyph
            variants.add(sld[:i] + GLYPH_SWAPS[sld[i]] + sld[i + 1:])

    for i in range(1, len(sld)):                                 # hyphenation
        variants.add(f"{sld[:i]}-{sld[i:]}")

    variants.discard(sld)
    return {f"{v}.{tld}" for v in variants if v and "." not in v}


def resolve(domain: str) -> str | None:
    """Return the first resolved IP for domain, or None."""
    try:
        return socket.getaddrinfo(domain, None)[0][4][0]
    except (socket.gaierror, OSError):
        return None


def scan_permutations(domain: str, max_workers: int = 20) -> dict[str, str]:
    """Return {registered lookalike domain: resolved IP}."""
    candidates = sorted(generate_permutations(domain))
    registered: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for candidate, ip in zip(candidates, pool.map(resolve, candidates)):
            if ip:
                registered[candidate] = ip
    return registered
