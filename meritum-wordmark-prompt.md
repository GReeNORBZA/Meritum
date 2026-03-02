# Meritum Wordmark — Design Prompt

## Task

Design a custom SVG wordmark for "Meritum" — a self-serve medical billing platform for Alberta physicians. The wordmark is the entire brand identity; there is no separate logomark, icon, or symbol. The name is the brand.

## Output

Produce 3 SVG variants of the wordmark, each with a different subtle typographic detail. Each variant must be delivered as:

1. A clean, production-ready SVG file (hand-crafted paths, not traced from a font render)
2. Two colour versions: primary (`#1B2A4A` deep navy on transparent) and reversed (`#FAFAF8` warm off-white on transparent)
3. An accent version where a single typographic detail element uses `#C2973E` (warm brass/amber) — e.g., the custom M stroke, a ligature connector, or a crossbar

Save all SVG files to `/home/developer/projects/meritum-wordmark/`.

## Design Direction

**Typeface foundation:** Satoshi Bold. The wordmark should feel like it evolved from Satoshi — someone who knows type would recognise the DNA, but the letterforms have been refined into something custom. Not a font render with tweaks; a proper wordmark.

**Typographic details to explore (one per variant):**

- **Variant A — Modified M:** A subtle alteration to the capital M. Options: slightly angled middle vertex that doesn't descend fully to the baseline (creating a distinctive notch), or a widened M with custom stroke weight distribution. The M is the first letter and the visual anchor.

- **Variant B — Custom ligature:** A connection between two adjacent letters. The "ri" pair or the "tu" pair are natural candidates. The ligature should be understated — a shared stroke or a subtle join, not a decorative flourish. Think of how the Figma wordmark handles letter connections.

- **Variant C — Crossbar detail:** A modified crossbar on the "t" that extends slightly to interact with an adjacent letter, or a "t" with a distinctive terminal. Alternatively, a subtle ink trap or optical correction on the "m" (final letter) that gives the wordmark a custom feel without being obvious.

## Constraints

- **Clean and confident.** Think Stripe, Linear, Notion — the name is the brand. No decoration.
- **Letter-spacing:** Slightly wide (`~0.04em` equivalent), even across all letters. The wordmark must be legible at small sizes (32px height in a nav bar).
- **Weight:** Bold / semibold range. Authoritative without being heavy.
- **No italics, no decorative serifs, no gradients, no shadows, no outlines.**
- **No icon or symbol.** The wordmark stands alone.
- **Geometric / neo-grotesque feel.** Not humanist, not handwritten, not playful.
- **The custom detail should be noticeable on second look, not first.** It should feel like taste, not design. A physician should register it as "that looks professional" without consciously analysing why.

## Brand Context

- **Audience:** Alberta physicians. They distrust marketing. Medical software logos universally involve clipart stethoscopes and heartbeat lines; Meritum goes in the opposite direction entirely.
- **Tone:** Professional, confident, restrained. Not flashy, not corporate, not startup-y.
- **Colour palette:** Deep navy primary (#1B2A4A), warm brass accent (#C2973E), warm off-white background (#FAFAF8). The wordmark lives primarily in navy on off-white.
- **The word "Meritum"** is Latin for "earned" / "deserved." The brass/amber accent carries connotations of earned value and merit. If the accent colour appears in the wordmark, it should feel intentional and sparing — a single element, not a gradient or a full letter.

## Technical Requirements

- SVG paths, not text elements (the wordmark must render without font dependencies)
- `viewBox` set for proper scaling
- No embedded fonts or font references
- Clean, minimal SVG markup (no generator bloat, no unnecessary groups)
- Each SVG should work at sizes from 24px height (favicon context) to 200px height (hero context)
- Ensure the SVG has appropriate `aria-label="Meritum"` for accessibility

## Usage Context

The wordmark will be used in:
- Navigation bar (left-aligned, ~32–40px height)
- Footer (~24–32px height)
- Favicon (the M only, at 16-32px)
- OG image / social cards (centred, ~80px height)
- The hero section of the About page (optional, larger treatment)

For the favicon, also produce a standalone "M" glyph extracted from the wordmark, optimised for 16x16 and 32x32 rendering.

## What NOT to Do

- Do not use a font rendering tool and export to SVG. Hand-craft the paths.
- Do not add any visual element beyond the letterforms (no underlines, no boxes, no containing shapes).
- Do not use more than one accent colour element per variant.
- Do not make the custom detail so subtle that it's invisible, or so prominent that it looks like a logo. The sweet spot is "I can tell someone designed this."
