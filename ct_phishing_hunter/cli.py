"""ct-phishing-hunter CLI."""

import click

from .crtsh import recent_cert_domains
from .matcher import Match, score_against_brands, score_domain
from .permutations import generate_permutations, scan_permutations


def _print_match(match: Match, extra: str = "") -> None:
    color = "red" if match.score >= 80 else "yellow"
    click.secho(f"[{match.score:3}] {match.kind:15} {match.domain}  — {match.reason}{extra}", fg=color)


@click.group()
def cli() -> None:
    """Hunt phishing/lookalike domains targeting your brands."""


@cli.command()
@click.argument("domain")
@click.option("--brand", "-b", required=True, help="Brand name to score against (e.g. acmecorp).")
def score(domain: str, brand: str) -> None:
    """Explain how DOMAIN scores against a brand."""
    match = score_domain(domain, brand)
    if match:
        _print_match(match)
    else:
        click.secho(f"{domain}: no lookalike signal for brand '{brand}'", fg="green")


@cli.command()
@click.option("--brand", "-b", required=True, multiple=True, help="Brand to protect (repeatable).")
@click.option("--allow", "-a", multiple=True, help="Legit domain to ignore (repeatable).")
@click.option("--days", default=90, show_default=True, help="Only certs issued in the last N days.")
def sweep(brand: tuple[str, ...], allow: tuple[str, ...], days: int) -> None:
    """Search Certificate Transparency (crt.sh) for lookalike certs."""
    allowlist = {a.lower() for a in allow}
    total_matches = 0
    for b in brand:
        click.echo(f"sweeping CT logs for '{b}' (last {days} days)...")
        domains = recent_cert_domains(b, days=days)
        click.echo(f"  {len(domains)} certificate names mention '{b}'")
        for domain, last_seen in sorted(domains.items()):
            for match in score_against_brands(domain, [b], allowlist):
                total_matches += 1
                _print_match(match, extra=f"  (cert seen {last_seen[:10]})")
    if total_matches == 0:
        click.secho("no suspicious lookalike certificates found.", fg="green")
    else:
        click.echo(f"\n{total_matches} suspicious certificate name(s).")


@cli.command()
@click.argument("domain")
@click.option("--list-only", is_flag=True, help="Print candidates without resolving them.")
def permutations(domain: str, list_only: bool) -> None:
    """Generate typo/homoglyph variants of DOMAIN and find registered ones."""
    candidates = generate_permutations(domain)
    click.echo(f"{len(candidates)} permutations of {domain}")
    if list_only:
        for c in sorted(candidates):
            click.echo(f"  {c}")
        return
    click.echo("resolving (registered lookalikes are the ones that answer)...")
    registered = scan_permutations(domain)
    if not registered:
        click.secho("none currently resolve — no registered lookalikes.", fg="green")
        return
    for d, ip in sorted(registered.items()):
        click.secho(f"  REGISTERED  {d:30} -> {ip}", fg="red")
    click.echo(f"\n{len(registered)} registered lookalike(s) — investigate ownership before assuming malice.")


@cli.command()
@click.option("--server", required=True, help="certstream-compatible WebSocket URL (self-hosted).")
@click.option("--brand", "-b", required=True, multiple=True)
@click.option("--allow", "-a", multiple=True)
def watch(server: str, brand: tuple[str, ...], allow: tuple[str, ...]) -> None:
    """Score every cert on a live certstream feed the moment it is issued."""
    from .livestream import stream_cert_domains

    allowlist = {a.lower() for a in allow}
    click.echo(f"streaming certs from {server} — watching brands: {', '.join(brand)}")
    seen = 0
    try:
        for domains in stream_cert_domains(server):
            seen += len(domains)
            for domain in domains:
                for match in score_against_brands(domain, list(brand), allowlist):
                    _print_match(match)
    except KeyboardInterrupt:
        click.echo(f"\nstopped after scoring {seen} certificate names.")


if __name__ == "__main__":
    cli()
