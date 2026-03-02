#!/usr/bin/env python3
"""
Generate Meritum wordmark SVGs.

- Favicon: hand-crafted M glyph path in brass
- Wordmark: Satoshi Bold text element, three color versions
"""
import os

NAVY  = "#1B2A4A"
WHITE = "#FAFAF8"
BRASS = "#C2973E"
OUT   = "/home/developer/projects/meritum-wordmark"


def favicon_m():
    """Hand-crafted M glyph — variant A raised-vertex notch, brass."""
    # Metrics: cap 0–680, stem 108, shallow V vertex at 380/230
    w, h = 660, 680
    d = (
        "M0 680L0 0L330 380L660 0L660 680Z"
        "M108 680L108 380L330 230L552 380L552 680Z"
    )
    pad = 60
    vb = f"{-pad} {-pad} {w + 2*pad} {h + 2*pad}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}" aria-label="M">\n'
        f'  <path fill="{BRASS}" fill-rule="evenodd" d="{d}"/>\n'
        f'</svg>\n'
    )


def wordmark(fill):
    """Meritum wordmark using Satoshi Bold text."""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 80" aria-label="Meritum">\n'
        f'  <text x="0" y="62" font-family="Satoshi, sans-serif" font-weight="700"'
        f' font-size="68" letter-spacing="2.5" fill="{fill}">Meritum</text>\n'
        f'</svg>\n'
    )


def wordmark_accent():
    """Meritum wordmark — M in brass, rest in navy."""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 80" aria-label="Meritum">\n'
        f'  <text x="0" y="62" font-family="Satoshi, sans-serif" font-weight="700"'
        f' font-size="68" letter-spacing="2.5" fill="{NAVY}">Meritum</text>\n'
        f'  <text x="0" y="62" font-family="Satoshi, sans-serif" font-weight="700"'
        f' font-size="68" letter-spacing="2.5" fill="{BRASS}">M</text>\n'
        f'</svg>\n'
    )


def out(name, content):
    path = os.path.join(OUT, name)
    with open(path, "w") as f:
        f.write(content)
    print(f"  ✓ {name}")


def main():
    os.makedirs(OUT, exist_ok=True)

    print("Favicon:")
    out("favicon-m.svg", favicon_m())

    print("\nWordmark:")
    out("wordmark-primary.svg",  wordmark(NAVY))
    out("wordmark-reversed.svg", wordmark(WHITE))
    out("wordmark-accent.svg",   wordmark_accent())

    print(f"\n✓ All files → {OUT}")


if __name__ == "__main__":
    main()
