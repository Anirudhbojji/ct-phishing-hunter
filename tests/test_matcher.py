"""Offline tests for lookalike scoring and permutation generation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ct_phishing_hunter.matcher import levenshtein, normalize, score_domain
from ct_phishing_hunter.permutations import generate_permutations


# --- scoring ---

def test_homoglyph_detected():
    match = score_domain("acmec0rp.com", "acmecorp")  # 0 -> o
    assert match and match.kind == "homoglyph" and match.score >= 90


def test_rn_for_m_homoglyph():
    match = score_domain("ternporal.com", "temporal")
    assert match and match.kind == "homoglyph"


def test_typosquat_detected():
    match = score_domain("acmecrop.com", "acmecorp")  # transposition
    assert match and match.kind == "typosquat"


def test_brand_token_detected():
    match = score_domain("acmecorp-login.com", "acmecorp")
    assert match and match.kind == "brand_token"


def test_subdomain_spoof_detected():
    match = score_domain("acmecorp.evil-site.com", "acmecorp")
    assert match and match.kind == "subdomain_spoof"


def test_unrelated_domain_ignored():
    assert score_domain("wikipedia.org", "acmecorp") is None


def test_brands_own_domain_not_flagged():
    assert score_domain("acmecorp.com", "acmecorp") is None


def test_allowlist_respected():
    assert score_domain("portal.acmecorp.net", "acmecorp", allowlist={"acmecorp.net"}) is None


def test_short_brands_do_not_typosquat_match():
    # edit-distance matching on short names would flood with false positives
    assert score_domain("abcd.com", "abc") is None


def test_wildcard_cert_name_handled():
    match = score_domain("*.acmec0rp.com", "acmecorp")
    assert match and match.kind == "homoglyph"


# --- helpers ---

def test_normalize():
    assert normalize("acmec0rp") == "acmecorp"   # 0 -> o
    assert normalize("g00gle") == "google"
    assert normalize("acrnecorp") == "acmecorp"  # rn -> m
    # "1" maps to "l" not "i"; 1-for-i substitutions are caught by edit distance
    assert normalize("acmec1rp") != "acmecorp"


def test_levenshtein():
    assert levenshtein("acmecorp", "acmecorp") == 0
    assert levenshtein("acmecorp", "acmecrop") == 2  # transposition = 2 single edits
    assert levenshtein("acmecorp", "acmecor") == 1


# --- permutations ---

def test_permutations_contain_classic_typos():
    variants = generate_permutations("acmecorp.com")
    assert "cmecorp.com" in variants       # omission
    assert "camecorp.com" in variants      # transposition
    assert "acmec0rp.com" in variants      # homoglyph (o -> 0)
    assert "acme-corp.com" in variants     # hyphenation
    assert "acmecorp.com" not in variants  # never includes the original


def test_permutations_keep_tld():
    assert all(v.endswith(".com") for v in generate_permutations("acmecorp.com"))
