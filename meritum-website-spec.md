# Meritum Marketing Website — Technical Specification

> Build specification for meritum.ca marketing site. Synthesised from all source documents (website build prompt, homepage copy v5, how-it-works v1, pricing page v3, brand context, pricing strategy v2, pricing gap closure spec) and conversation decisions with the founder.

---

## 1. Overview

A five-page marketing website for Meritum Health Technologies, plus blog infrastructure, legal page placeholders, a contact form, and a custom 404 page. The site's job is to convert Alberta physicians from awareness to signup. The primary conversion mechanism is an interactive billing cost calculator; the secondary mechanism is the early bird scarcity counter (first 100 physicians at $199/month).

**Not in scope:** The Meritum application itself, the app backend, user authentication, or any PHI handling. This is a static marketing site with two interactive components.

---

## 2. Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Framework | Astro | Static-first, ships near-zero JS, markdown blog built-in, Lighthouse 95+ trivially. Five static pages don't need Next.js. |
| Repository | Separate repo (`meritum-website`) | No reason to couple a static marketing site to the app monorepo. |
| CSS | Tailwind CSS 4.x | Design tokens via `@theme`, consistent with main app's stack, utility-first produces maintainable output for a solo developer. |
| Hosting | Cloudflare Pages | Free tier, global CDN with Canadian edge POPs, automatic HTTPS, preview deployments per branch. |
| Analytics | Plausible (self-hosted) | Open source, no cookies, no consent banner. Docker-isolated on the same DO droplet as the app. |
| Fonts | Self-hosted (Satoshi + IBM Plex Sans) | `font-display: swap`, Latin subset, no third-party CDN dependency. |
| Contact form | Basic HTML form → placeholder email | Formspree or Cloudflare Workers handler. No backend dependency. |
| Blog | Astro Content Collections (markdown) | Built-in frontmatter validation, automatic type safety, zero CMS dependency. |

---

## 3. Site Map

```
meritum.ca/
├── /                       Home (7 sections, long scroll)
├── /how-it-works           How It Works (7 sections)
├── /pricing                Pricing (9 sections)
├── /about                  About (single scroll, first-person)
├── /blog                   Blog index
├── /blog/{slug}            Individual blog posts
├── /privacy                Privacy Policy (content TBD)
├── /terms                  Terms of Service (content TBD)
├── /contact                Contact form
└── /404                    Custom 404 (content TBD)
```

**Total: 7 built pages + blog template + 2 legal placeholders + 404 + RSS feed**

---

## 4. Design System

### 4.1 Colour Tokens

```
--color-primary:      #1B2A4A    /* Deep navy. Headers, nav, primary surfaces, text on light. */
--color-accent:       #C2973E    /* Warm brass/amber. CTAs, highlights, wordmark accent. Sparingly. */
--color-background:   #FAFAF8    /* Warm off-white. Page background. */
--color-surface:      #F0EFEC    /* Light warm grey. Cards, calculator, inputs, pricing cards. */
--color-text:         #1A1A2E    /* Near-black. Primary body text. */
--color-text-muted:   #5A5A6E    /* Muted text for captions, secondary labels. */
--color-success:      #2D6A4F    /* Forest green. WCAG AA on both backgrounds. */
--color-error:        #C1292E    /* Warm red. WCAG AA on both backgrounds. */
--color-accent-hover: #A87E33    /* Darker brass for hover/focus states on accent elements. */
--color-primary-light:#2A3D66    /* Lighter navy for hover states. */
```

Contrast verification (WCAG AA, 4.5:1 minimum for normal text):
- `#1B2A4A` on `#FAFAF8`: 11.2:1 (passes AAA)
- `#1A1A2E` on `#FAFAF8`: 14.8:1 (passes AAA)
- `#C2973E` on `#1B2A4A`: 4.7:1 (passes AA — accent on primary)
- `#2D6A4F` on `#FAFAF8`: 6.3:1 (passes AA)
- `#2D6A4F` on `#F0EFEC`: 5.8:1 (passes AA)
- `#C1292E` on `#FAFAF8`: 5.6:1 (passes AA)
- `#C1292E` on `#F0EFEC`: 5.2:1 (passes AA)

### 4.2 Typography

| Role | Typeface | Weight | Usage |
|------|----------|--------|-------|
| Display / headlines / wordmark | Satoshi | Medium (500), Bold (700) | Page titles, section headlines, wordmark, display text |
| Body / UI / secondary | IBM Plex Sans | Regular (400), Medium (500) | Body copy, navigation, buttons, form labels, captions, UI text |

**Type scale** (based on 1rem = 16px, major third ratio 1.25):

```
--text-xs:    0.75rem / 1rem        /* 12px — captions, fine print */
--text-sm:    0.875rem / 1.25rem    /* 14px — secondary text, nav */
--text-base:  1rem / 1.625rem       /* 16px — body copy (generous line height for readability) */
--text-lg:    1.25rem / 1.75rem     /* 20px — lead paragraphs */
--text-xl:    1.5rem / 2rem         /* 24px — section subheads */
--text-2xl:   1.875rem / 2.25rem    /* 30px — section headlines */
--text-3xl:   2.25rem / 2.5rem      /* 36px — page titles (mobile) */
--text-4xl:   3rem / 3.25rem        /* 48px — page titles (desktop) */
--text-5xl:   3.75rem / 4rem        /* 60px — hero headline */
```

**Font loading:**
- Self-host both typefaces in `/public/fonts/`
- `@font-face` declarations with `font-display: swap`
- Subset to Latin characters
- WOFF2 format only (universal browser support, smallest file size)
- Preload display font weights used above the fold: Satoshi Bold (hero headline)

### 4.3 Spacing Scale

```
--space-1:   0.25rem   /* 4px */
--space-2:   0.5rem    /* 8px */
--space-3:   0.75rem   /* 12px */
--space-4:   1rem      /* 16px */
--space-6:   1.5rem    /* 24px */
--space-8:   2rem      /* 32px */
--space-12:  3rem      /* 48px */
--space-16:  4rem      /* 64px */
--space-20:  5rem      /* 80px */
--space-24:  6rem      /* 96px */
--space-32:  8rem      /* 128px */
```

Section vertical padding: `--space-20` (mobile), `--space-24` (desktop).
Max content width: `1200px`. Reading width (About page, blog posts): `680px`.

### 4.4 Wordmark

For the initial build: Satoshi Bold at display size, `letter-spacing: 0.04em`, rendered as text. The layout must accommodate an SVG replacement (the custom typographic detail will be built in a separate session and swapped in as an `<svg>` or `<img>` component).

Implementation: a `<Wordmark />` Astro component that renders text for now, with a clear swap point for SVG later.

### 4.5 Visual Textures

Subtle topographic contour patterns and fine grid textures for section backgrounds and decorative accents. Built as:

- **Topographic pattern:** SVG `<pattern>` element with thin curved contour lines (`stroke: currentColor`, `opacity: 0.04–0.06`). Tiles seamlessly. Used on alternating sections (Thursday Cycle, Social Proof).
- **Grid pattern:** CSS-only fine dot grid (`radial-gradient`, `opacity: 0.03–0.05`). Used as subtle section background alternative.

Both patterns must:
- Be resolution-independent (SVG/CSS, not raster)
- Tile/scale gracefully across viewport sizes
- Stay understated — texture, not content
- Use `currentColor` or palette colours at very low opacity

### 4.6 Favicon

Generated from the wordmark. Sizes: 16x16, 32x32, 180x180 (Apple touch icon), 192x192 (Android). Format: SVG primary (scales), PNG fallbacks. Colour: `#1B2A4A` on transparent, or `#C2973E` "M" on `#1B2A4A` background.

### 4.7 Default OG Image

1200x630px, `#1B2A4A` background, Satoshi Bold wordmark centred in `#FAFAF8`. Simple, clean, on-brand. Generated as a static asset, not dynamically rendered.

---

## 5. Page Specifications

### 5.1 Global Layout

**Header/Navigation:**
- Left: Wordmark (links to `/`)
- Centre-right: How It Works, Pricing, About, Blog
- Far right: CTA button
- CTA button text is dynamic (see Section 7 — Configuration)
- Mobile: hamburger menu; CTA button remains visible outside the menu at all viewport sizes
- Sticky header on scroll (subtle shadow on scroll, transparent at top)

**Footer:**
- Column 1: Wordmark + one-line description ("Alberta's self-serve medical billing platform")
- Column 2: Navigation links (How It Works, Pricing, About, Blog, Contact)
- Column 3: Legal links (Privacy Policy, Terms of Service) + contact email placeholder (`hello@meritum.ca`)
- Column 4: LinkedIn icon/link (placeholder URL)
- Bottom bar: `Copyright 2026 Meritum Health Technologies Inc. All rights reserved.` + `Plus 5% GST on all prices.`

**Skip-to-content link** on every page (WCAG 2.1 AA).

### 5.2 Homepage (`/`)

Seven sections in order. Each visually distinct (alternate `--color-background` and `--color-surface`, with topographic texture on select sections).

| Section | Content Source | Background | Key Implementation Notes |
|---------|--------------|------------|-------------------------|
| 1. Hero | homepage-copy-v5 S1 | `--color-background` | Full-bleed. One headline, one subhead, one CTA. No feature list, no images. CTA scrolls to calculator. |
| 2. Calculator | homepage-copy-v5 S2 + brand-context S6 | `--color-surface` | Two-tab interactive component. See Section 6.1. |
| 3. Three Pillars | homepage-copy-v5 S3 | `--color-background` | Three equal-weight prose blocks. No cards, no icons, no illustrations. |
| 4. Thursday Cycle | homepage-copy-v5 S4 | `--color-surface` + topographic texture | Stepped timeline / vertical sequence. Four steps with bold label + body paragraph. |
| 5. Objection Busters | homepage-copy-v5 S5 | `--color-background` | Five blocks. Question as heading (in quotes), answer as paragraph. Not an accordion — conversational, distinct from pricing FAQ. |
| 6. Social Proof / Early Bird | homepage-copy-v5 S6 | `--color-primary` (dark section) | Live early bird counter. Light text on navy. See Section 6.2. |
| 7. Final CTA | homepage-copy-v5 S7 | `--color-surface` | Full-width. One headline, one supporting line, one CTA button with dynamic rate. |

### 5.3 How It Works (`/how-it-works`)

Seven sections.

| Section | Content Source | Notes |
|---------|--------------|-------|
| 1. Page Header | how-it-works S1 | Headline + intro paragraph |
| 2. Onboarding | how-it-works S2 | Four steps — compact stepped layout. Should feel fast. Brief delegate mention at the end (one sentence, no heading). |
| 3. Your Day with Meritum | how-it-works S3 | Three subsections (EMR import, mobile entry, manual entry). Implement as tabs or scrolling sequence. |
| 4. Thursday Cycle | how-it-works S4 | Expanded from homepage S4. Rules engine detail, advice engine, three submission preference modes. |
| 5. After Submission | how-it-works S5 | Assessment matching, rejection analytics, PCPCM reconciliation. |
| 6. What Doesn't Change | how-it-works S6 | Short reassurance section. |
| 7. CTA | how-it-works S7 | Dynamic rate. Secondary link to homepage calculator. |

### 5.4 Pricing (`/pricing`)

Nine sections.

| Section | Content Source | Notes |
|---------|--------------|-------|
| 1. Header | pricing-page S1 | Direct headline + subhead |
| 2. Individual Pricing | pricing-page S2 | Two cards side-by-side (early bird + standard). Early bird emphasised while spots remain. Early bird counter displayed here. See Section 6.3. |
| 3. Practice Pricing | pricing-page S3 | Practice tier rate table. Separate from individual. |
| 4. What's Included | pricing-page S4 | Single column feature list with bold lead-ins. Not a checklist grid. |
| 5. Comparisons | pricing-page S5 | Two tables: vs. billing agent (9 rows), vs. self-serve software (11 rows). Clean, readable. Mobile: stacked cards or horizontal-scroll. Not a marketing feature grid. |
| 6. The Math | pricing-page S6 | Two worked examples (GP $400K, specialist $800K). Link to calculator. |
| 7. Referral | pricing-page S7 | Callout module between math and FAQ. |
| 8. FAQ | pricing-page S8 | Nine questions. Accordion: question as trigger, answer expands. All collapsed by default. Keyboard navigable, ARIA attributes. FAQ schema markup (see Section 9). |
| 9. CTA | pricing-page S9 | Dynamic rate, same pattern as other page CTAs. |

### 5.5 About (`/about`)

Single scroll page. Content from homepage-copy-v5 About Page section.

- No sidebar, no feature callouts, no mid-page CTAs
- First-person voice throughout
- Max reading width: `680px`
- Generous whitespace, no decorative elements
- CTA at bottom links to homepage calculator (not signup)
- The quietest page on the site: confident, restrained

### 5.6 Blog (`/blog` + `/blog/{slug}`)

**Index page:**
- Post cards: title, date, excerpt, "Read more" link
- Layout that works with one post and scales to many (no empty-state awkwardness)
- Sorted by date, newest first

**Post template:**
- Comfortable reading width (`680px` max)
- Generous line height (`--text-base` at 1.625 line height)
- Clear heading hierarchy (h1 = title, h2/h3 for content structure)
- Frontmatter: `title`, `date`, `description`, `author` (optional)
- Rendered from Markdown via Astro Content Collections

**RSS feed:** `/rss.xml` — generated by `@astrojs/rss`. Includes title, date, description, full content link.

### 5.7 Contact (`/contact`)

Simple contact form:
- Fields: Name, Email, Message (all required)
- Submit button: "Send Message"
- Success state: "Message sent. We'll respond within one business day."
- Error state: "Something went wrong. Please email us at hello@meritum.ca."
- Form handler: Cloudflare Workers (serverless function on the same CF Pages project) or Formspree as a fallback. No app backend dependency.
- Spam prevention: honeypot field (hidden), no CAPTCHA.

### 5.8 Legal Pages (`/privacy`, `/terms`)

Placeholder pages with:
- Page title (Privacy Policy / Terms of Service)
- Body text: "This page is being finalised. For questions, contact hello@meritum.ca."
- Same layout as About page (reading width, generous whitespace)
- Content will be swapped in when provided by the founder

### 5.9 404 Page

Custom 404 with on-brand styling. Content placeholder until founder provides copy. Default: "Page not found." with a link back to the homepage. Same global header/footer.

---

## 6. Interactive Components

### 6.1 Calculator (Homepage Section 2)

**Architecture:** Astro island with `client:visible` directive. Framework: Preact (smallest runtime, ~3KB). The calculator is the only component on the homepage that requires client-side JS.

**Tab A: Billing Agent Comparison**

Inputs:
- Estimated annual AHCIP billings: slider + numeric input, synced. Default `$400,000`. Range `$100,000–$2,000,000`. Step `$10,000`.
- Agent's percentage fee: slider + numeric input, synced. Default `4%`. Range `3–5%`. Step `0.5%`.

Outputs (calculated in real time on every input change):
- Annual agent cost: `billings * percentage`
- Meritum annual cost: from config (`$2,388` during early bird, `$3,181` after)
- Annual saving: `agent cost - Meritum cost`

Display: saving shown prominently in `--color-accent` with large type.

Below output: supporting line from homepage-copy-v5 S2 ("That's what you're paying for someone to submit claims...").

CTA below calculator: "Start today" with current dynamic rate.

**Tab B: Self-Serve Software Comparison**

No calculator. Renders as editorial content: three billing examples (03.01AA after-hours modifier, volume specialty scale, RRNP auto-calculation) + closing paragraph + CTA. Copy from brand-context S6 Path B. Styled as prose, not a card.

**Accessibility:** Slider has `aria-label`, linked to numeric input. Tab interface uses `role="tablist"`, `role="tab"`, `role="tabpanel"` with `aria-selected`. Keyboard navigable: arrow keys switch tabs, tab key moves to content.

### 6.2 Early Bird Counter (Homepage Section 6 + Pricing Section 2)

Displays: "XX of 100 early bird spots remaining."

**Data source architecture:**

```
1. On page load: read from config default (100)
2. Fetch from app backend: GET app.meritum.ca/api/v1/public/early-bird-count
   → Response: { data: { remaining: 82, total: 100 } }
3. On success: update displayed count
4. On failure (app not deployed, network error): keep config default
```

The backend endpoint (`/api/v1/public/early-bird-count`) is a public, unauthenticated, read-only endpoint that returns the count. It queries `countEarlyBirdSubscriptions()` from the platform repository (already exists per Pricing Gap Closure Spec) and returns `100 - count`.

**Counter rendering:**
- Number animated on load (count up from 0 to current value, ~1.5s)
- When < 20 remaining: add subtle urgency (slightly larger number, no colour change — scarcity does the work without manipulation)
- When 0 remaining: entire early bird UI switches to standard rate presentation (driven by config, see Section 7)

**Implementation:** Preact island with `client:load`. Polls on page load only (not real-time WebSocket — the counter changes by at most a few per day).

### 6.3 Pricing Cards (Pricing Section 2)

Two cards side-by-side:
- **Early bird** (visually emphasised while spots remain): subtle `--color-accent` border or badge
- **Standard** (secondary while early bird is open)

When early bird fills (counter reaches 0): standard card becomes primary, early bird card is hidden entirely.

Each card includes the "Everything included" feature line from pricing-page S2.

### 6.4 Comparison Tables (Pricing Section 5)

Two tables from pricing-page S5:
- Meritum vs. billing agent (9+ rows)
- Meritum vs. self-serve software (11 rows)

**Responsive strategy:** On mobile (< 768px), render as stacked cards (one card per row) rather than a truncated table. Each card shows the comparison dimension as a heading, with the two options as labelled values below.

### 6.5 FAQ Accordion (Pricing Section 8)

Nine questions from pricing-page S8.
- All collapsed by default
- Single-expand (opening one closes others) or multi-expand (user's choice) — implement as multi-expand (less frustrating)
- `<details>` + `<summary>` as the base (progressive enhancement, works without JS)
- Enhanced with smooth expand/collapse animation via CSS `transition` on `grid-template-rows`
- ARIA: `aria-expanded` on trigger, `aria-controls` pointing to answer panel
- Keyboard: Enter/Space toggles, focus visible on trigger

### 6.6 Daily Workflow Tabs (How It Works Section 3)

Three subsections (EMR import, mobile entry, manual entry) rendered as a tabbed interface.
- Same tab pattern as calculator: `role="tablist"`, keyboard navigable
- Preact island with `client:visible`
- Fallback (no JS): all three sections visible in sequence

---

## 7. Configuration System

A single configuration object drives all dynamic content. Every element that changes based on early bird state reads from this config.

**File:** `src/config/pricing.ts`

```typescript
export const pricingConfig = {
  earlyBird: {
    active: true,                    // Set to false when spots fill
    spotsTotal: 100,
    spotsRemaining: 100,             // Default; overridden by API fetch
    monthlyRate: 199,
    annualRate: 2388,
    rateLockMonths: 12,
  },
  standard: {
    monthlyRate: 279,
    annualRate: 3181,
    annualDiscountPercent: 5,
  },
  practice: {
    minimumPhysicians: 5,
    monthlyRate: 251.10,
    annualRate: 2863,
    clinicDiscountPercent: 10,
    maxDiscountPercent: 15,
  },
  currency: 'CAD',
  gstPercent: 5,
  earlyBirdCountEndpoint: 'https://app.meritum.ca/api/v1/public/early-bird-count',
} as const;
```

**Dynamic elements driven by this config:**

| Element | During early bird (`active: true`) | After early bird (`active: false`) |
|---------|----------------------------------|-----------------------------------|
| Nav CTA | "Start Today — $199/month" | "Start Today — $279/month" |
| Early bird counter | "XX of 100 spots remaining" | Hidden |
| Pricing card emphasis | Early bird card primary | Standard card primary; early bird card hidden |
| Calculator Meritum cost | $2,388/year | $3,181/year |
| Homepage final CTA rate | $199/month | $279/month, or save 5% annually |
| Pricing page CTA rate | $199/month | $279/month, or save 5% annually |
| How It Works CTA rate | $199/month | $279/month, or save 5% annually |

**Transition mechanism:** When the early bird count API returns `remaining: 0`, the client-side code sets `earlyBird.active = false` and all dynamic elements update. For the static build, `earlyBird.active` can be toggled manually in the config file and the site rebuilt/redeployed (Cloudflare Pages deploys in ~30 seconds).

---

## 8. Content Integration

### 8.1 Copy Sources

All copy is production-ready and used verbatim. Implementation notes (italicised in source documents) are layout/behaviour instructions, not rendered content.

| Page | Source Document | Sections |
|------|----------------|----------|
| Homepage | meritum-homepage-copy-v5.docx | S1–S7 |
| About | meritum-homepage-copy-v5.docx | About Page section |
| How It Works | meritum-how-it-works-v1.docx | S1–S7 |
| Pricing | meritum-pricing-page-v3.docx | S1–S9 |
| Calculator (Tab B) | meritum-brand-context.docx | S6, Path B |

### 8.2 Copy Discrepancy Resolution

One discrepancy found across documents:
- **Annual pricing:** Brand context doc (S1) says `$2,790/year`. Pricing Gap Closure Spec (B0-1) corrects this to `$3,181/year`. Pricing page copy v3 already uses `$3,181/year`. **Resolution:** Use `$3,181/year` throughout. The brand context doc has a stale value.

### 8.3 Content Rules

- No emoji in any copy or UI element
- No "AI" terminology. Use: rules engine, advice engine, billing optimisation, pattern analysis
- No US statistics or US healthcare references
- No free trial messaging
- No feature-gating UI
- Minimise em dashes; use semicolons or colons
- All prices in CAD, exclusive of GST unless explicitly stated
- Two typefaces maximum (Satoshi + IBM Plex Sans)

---

## 9. SEO and Structured Data

### 9.1 Meta Tags

Every page gets:
- `<title>` — unique, under 60 characters
- `<meta name="description">` — unique, under 160 characters
- `<meta property="og:title">`, `og:description`, `og:image`, `og:url`, `og:type`
- `<meta name="twitter:card" content="summary_large_image">`
- `<link rel="canonical" href="...">`

**Page titles:**
| Page | Title |
|------|-------|
| Home | Meritum — Alberta's Self-Serve Medical Billing Platform |
| How It Works | How It Works — Meritum |
| Pricing | Pricing — Meritum |
| About | About — Meritum |
| Blog | Blog — Meritum |
| Blog post | {Post Title} — Meritum Blog |
| Contact | Contact — Meritum |
| Privacy | Privacy Policy — Meritum |
| Terms | Terms of Service — Meritum |

### 9.2 Structured Data

**Organization schema** (site-wide, in `<head>`):
```json
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "Meritum Health Technologies Inc.",
  "url": "https://meritum.ca",
  "logo": "https://meritum.ca/og-image.png",
  "description": "Self-serve medical billing platform for Alberta physicians",
  "address": {
    "@type": "PostalAddress",
    "addressCountry": "CA",
    "addressRegion": "AB"
  }
}
```

**FAQ schema** (pricing page only, the 9 FAQ items):
```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "Why isn't there a free trial?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "..."
      }
    }
  ]
}
```

### 9.3 Technical SEO

- `sitemap.xml` — auto-generated by `@astrojs/sitemap`
- `robots.txt` — allow all, reference sitemap
- Blog posts with proper heading hierarchy (single h1, logical h2/h3 nesting)
- Canonical URLs on every page
- No duplicate content across pages

---

## 10. Analytics — Plausible (Self-Hosted)

### 10.1 Infrastructure

- Runs on the same DO droplet as the Meritum app, in a separate Docker container
- Subdomain: `analytics.meritum.ca`
- Own PostgreSQL database (separate from the app's managed DB) — or Plausible's embedded ClickHouse
- Reverse proxy: Caddy (automatic HTTPS via Let's Encrypt, simpler config than nginx)

### 10.2 Docker Compose

Delivered as `plausible/docker-compose.yml`:
- Plausible CE container
- ClickHouse container (Plausible's analytics database)
- Caddy reverse proxy routing `analytics.meritum.ca` to the Plausible container
- Persistent volumes for data

### 10.3 Tracking Integration

Script tag in the Astro site's `<head>` (all pages):
```html
<script defer data-domain="meritum.ca" src="https://analytics.meritum.ca/js/script.js"></script>
```

No cookies, no consent banner. Privacy-first by design.

### 10.4 Custom Events (Optional)

Track key conversion actions via Plausible's custom events API:
- `Calculator Interaction` — user adjusts a slider
- `CTA Click` — user clicks any "Start Today" button
- `FAQ Expand` — user opens an FAQ item
- `Tab Switch` — user switches calculator tabs

---

## 11. DNS and Deployment

### 11.1 DNS Configuration (Cloudflare)

| Record | Type | Name | Value | Proxy |
|--------|------|------|-------|-------|
| Root | CNAME | `@` | `meritum-website.pages.dev` (CF Pages) | Proxied |
| App | A | `app` | DO droplet IP | Proxied |
| Analytics | A | `analytics` | DO droplet IP | Proxied |
| WWW redirect | CNAME | `www` | `meritum.ca` | Proxied |
| Email (future) | MX | `@` | Mail provider (Postmark, etc.) | DNS only |

Cloudflare page rule: redirect `www.meritum.ca/*` to `https://meritum.ca/$1` (301).

### 11.2 Cloudflare Pages Setup

- Connect to GitHub repo `meritum-website`
- Build command: `npm run build` (or `pnpm build`)
- Build output directory: `dist/`
- Production branch: `main`
- Preview branches: all other branches (accessible only to you during development)
- Custom domain: `meritum.ca`

### 11.3 Deployment Flow

```
Developer pushes to main
  → Cloudflare Pages builds Astro site (~30s)
  → Deploys to global CDN
  → Available at meritum.ca
```

Preview deployments on branches give you a unique URL to review before merging to main.

---

## 12. Accessibility (WCAG 2.1 AA)

| Requirement | Implementation |
|-------------|---------------|
| Semantic HTML | `<header>`, `<nav>`, `<main>`, `<section>`, `<article>`, `<footer>` throughout |
| Skip-to-content | Hidden link, first focusable element, visible on focus |
| Keyboard navigation | All interactive elements (tabs, accordion, calculator, nav, forms) fully keyboard navigable |
| Focus indicators | Visible, consistent with brand (`2px solid --color-accent`, `2px offset`) |
| Colour contrast | All text/background combinations verified AA (see Section 4.1) |
| Status colours | Success/error paired with icons and labels (not colour alone) |
| Images | When added: meaningful `alt` text. Decorative images: `alt=""` or CSS |
| Motion | `prefers-reduced-motion` media query: disable animations for users who prefer reduced motion |
| Form labels | All form fields have visible `<label>` elements, associated via `for`/`id` |
| Error messages | Inline, associated with fields via `aria-describedby` |
| Language | `<html lang="en-CA">` |

---

## 13. Performance Targets

| Metric | Target |
|--------|--------|
| Lighthouse Performance (mobile) | 95+ |
| Lighthouse Accessibility | 100 |
| Lighthouse SEO | 100 |
| Total page weight (homepage, initial load) | < 500KB |
| Largest Contentful Paint | < 2.5s |
| Cumulative Layout Shift | < 0.1 |
| First Input Delay | < 100ms |
| Render-blocking resources | 0 |

**How we hit these:**
- Astro ships zero JS by default; only calculator and counter islands ship Preact (~3KB)
- Fonts self-hosted with `font-display: swap` and preloaded
- No third-party scripts except Plausible (~1KB)
- Images (when added): WebP/AVIF with responsive `srcset`
- SVG patterns (topographic/grid) are inline or tiny external files
- Cloudflare CDN handles edge caching and compression

---

## 14. Project Structure

```
meritum-website/
├── astro.config.mjs
├── package.json
├── tsconfig.json
├── tailwind.config.ts           # Design tokens, theme extension
├── public/
│   ├── fonts/
│   │   ├── satoshi-medium.woff2
│   │   ├── satoshi-bold.woff2
│   │   ├── ibm-plex-sans-regular.woff2
│   │   └── ibm-plex-sans-medium.woff2
│   ├── favicon.svg
│   ├── favicon-32.png
│   ├── favicon-16.png
│   ├── apple-touch-icon.png
│   ├── og-image.png
│   ├── robots.txt
│   └── patterns/
│       └── topographic.svg
├── src/
│   ├── config/
│   │   └── pricing.ts           # Single source of truth for dynamic values
│   ├── layouts/
│   │   ├── BaseLayout.astro     # HTML shell, head, meta, fonts, analytics
│   │   ├── PageLayout.astro     # Header + footer + main content slot
│   │   └── BlogLayout.astro     # Blog post layout (reading width)
│   ├── components/
│   │   ├── global/
│   │   │   ├── Header.astro
│   │   │   ├── Footer.astro
│   │   │   ├── Wordmark.astro
│   │   │   ├── NavCTA.astro     # Dynamic CTA button
│   │   │   ├── MobileMenu.astro
│   │   │   └── SkipToContent.astro
│   │   ├── home/
│   │   │   ├── Hero.astro
│   │   │   ├── Calculator.tsx   # Preact island
│   │   │   ├── ThreePillars.astro
│   │   │   ├── ThursdayCycle.astro
│   │   │   ├── ObjectionBusters.astro
│   │   │   ├── SocialProof.astro
│   │   │   ├── EarlyBirdCounter.tsx  # Preact island
│   │   │   └── FinalCTA.astro
│   │   ├── pricing/
│   │   │   ├── PricingCards.astro
│   │   │   ├── PracticeTable.astro
│   │   │   ├── ComparisonTable.astro
│   │   │   ├── WorkedExamples.astro
│   │   │   ├── ReferralCallout.astro
│   │   │   └── FAQAccordion.astro
│   │   ├── how-it-works/
│   │   │   ├── OnboardingSteps.astro
│   │   │   ├── DailyWorkflow.tsx  # Preact island (tabs)
│   │   │   ├── ThursdayCycleDetail.astro
│   │   │   └── AfterSubmission.astro
│   │   ├── contact/
│   │   │   └── ContactForm.astro
│   │   └── ui/
│   │       ├── Button.astro
│   │       ├── Section.astro    # Reusable section wrapper with background variants
│   │       ├── Container.astro  # Max-width wrapper
│   │       └── SectionHeading.astro
│   ├── pages/
│   │   ├── index.astro
│   │   ├── how-it-works.astro
│   │   ├── pricing.astro
│   │   ├── about.astro
│   │   ├── contact.astro
│   │   ├── privacy.astro
│   │   ├── terms.astro
│   │   ├── 404.astro
│   │   ├── blog/
│   │   │   ├── index.astro
│   │   │   └── [...slug].astro
│   │   └── rss.xml.ts
│   ├── content/
│   │   ├── config.ts            # Content collection schema
│   │   └── blog/                # Markdown blog posts go here
│   │       └── .gitkeep
│   └── styles/
│       └── global.css           # @font-face, base styles, Tailwind directives
├── plausible/
│   ├── docker-compose.yml       # Plausible + ClickHouse + Caddy
│   ├── Caddyfile                # Reverse proxy config
│   └── plausible-conf.env       # Plausible environment config (template)
└── docs/
    └── dns-setup.md             # DNS configuration instructions
```

---

## 15. Development Task Breakdown

Tasks are ordered for dependency resolution. Each task is independently testable.

### Phase 1: Foundation (Tasks 1–6)

| # | Task | Description | Depends On |
|---|------|-------------|-----------|
| 1 | Project scaffold | Init Astro project, install deps (Tailwind, Preact, @astrojs/sitemap, @astrojs/rss), configure `astro.config.mjs` and `tsconfig.json` | — |
| 2 | Font acquisition | Download Satoshi (Fontshare) and IBM Plex Sans (Google Fonts) WOFF2 files, subset to Latin, place in `/public/fonts/` | — |
| 3 | Design tokens | Configure Tailwind theme with all colour, typography, spacing, and breakpoint tokens from Section 4 | 1 |
| 4 | Global styles | `@font-face` declarations, CSS reset/base, Tailwind directives, topographic and grid pattern SVG/CSS | 2, 3 |
| 5 | Base layouts | `BaseLayout.astro` (HTML shell, head, meta, fonts, Plausible script), `PageLayout.astro` (header + footer + slot), `BlogLayout.astro` (reading width) | 3, 4 |
| 6 | Global components | `Header.astro`, `Footer.astro`, `Wordmark.astro`, `NavCTA.astro`, `MobileMenu.astro`, `SkipToContent.astro` | 5 |

### Phase 2: Configuration and Shared Components (Tasks 7–9)

| # | Task | Description | Depends On |
|---|------|-------------|-----------|
| 7 | Pricing config | Create `src/config/pricing.ts` with all dynamic values per Section 7 | 1 |
| 8 | UI components | `Button.astro`, `Section.astro`, `Container.astro`, `SectionHeading.astro` | 3 |
| 9 | SEO setup | Meta tag component, Organization schema, sitemap config, robots.txt | 5 |

### Phase 3: Static Pages (Tasks 10–15)

| # | Task | Description | Depends On |
|---|------|-------------|-----------|
| 10 | Homepage static sections | Hero, Three Pillars, Thursday Cycle, Objection Busters, Social Proof wrapper, Final CTA — all static Astro components with copy from source docs | 6, 7, 8 |
| 11 | How It Works page | All 7 sections as static Astro components with copy | 6, 7, 8 |
| 12 | Pricing page static sections | Header, Practice Pricing table, What's Included list, Comparison tables, Worked Examples, Referral callout, CTA | 6, 7, 8 |
| 13 | About page | Single scroll with copy from homepage-copy-v5 About section | 6, 8 |
| 14 | Contact page | Contact form with honeypot spam prevention | 6, 8 |
| 15 | Legal + 404 pages | Privacy, Terms (placeholder content), custom 404 | 6, 8 |

### Phase 4: Interactive Components (Tasks 16–20)

| # | Task | Description | Depends On |
|---|------|-------------|-----------|
| 16 | Calculator component | Preact island: two-tab interface, sliders, real-time calculation, Tab B editorial content | 7, 10 |
| 17 | Early bird counter | Preact island: fetch from API (fallback to config default), animated count, visibility in homepage and pricing page | 7, 10 |
| 18 | Pricing cards | Dynamic cards: early bird emphasis, standard secondary, swap on counter reaching 0 | 7, 12, 17 |
| 19 | FAQ accordion | `<details>`/`<summary>` base, CSS animation, ARIA attributes, FAQ schema markup | 12 |
| 20 | Daily workflow tabs | Preact island: three-tab interface for How It Works S3 | 11 |

### Phase 5: Blog Infrastructure (Tasks 21–23)

| # | Task | Description | Depends On |
|---|------|-------------|-----------|
| 21 | Content collection | Define blog collection schema in `src/content/config.ts` (title, date, description, author) | 5 |
| 22 | Blog index + post template | Blog index page with post cards, `[...slug].astro` dynamic route for individual posts | 5, 21 |
| 23 | RSS feed | `/rss.xml` endpoint via `@astrojs/rss` | 21, 22 |

### Phase 6: Assets and Polish (Tasks 24–27)

| # | Task | Description | Depends On |
|---|------|-------------|-----------|
| 24 | Favicon generation | SVG favicon + PNG fallbacks at 16, 32, 180, 192px | 4 |
| 25 | OG image | Default 1200x630 social card image | 4 |
| 26 | Accessibility audit | Manual pass: keyboard navigation, screen reader testing, contrast verification, focus indicators, `prefers-reduced-motion` | All above |
| 27 | Performance audit | Lighthouse run on all pages, fix any score < 95 | All above |

### Phase 7: Deployment Plumbing (Tasks 28–30)

| # | Task | Description | Depends On |
|---|------|-------------|-----------|
| 28 | Plausible Docker config | `docker-compose.yml`, `Caddyfile`, env template for self-hosted Plausible | — |
| 29 | DNS documentation | Step-by-step DNS setup guide for Cloudflare (meritum.ca, app.meritum.ca, analytics.meritum.ca, www redirect) | — |
| 30 | Cloudflare Pages deployment | Connect repo, configure build, set custom domain, verify preview deployments | 1–27 |

**Total: 30 tasks across 7 phases.**

---

## 16. CTA Destinations

All "Start Today" buttons link to: `https://app.meritum.ca/signup`

This will return a broken link / error until the app is deployed. That's expected during development. The URL is centralised in the pricing config for easy updating.

The About page CTA ("See what Meritum would save you") links to the homepage calculator section (`/#calculator`).

---

## 17. Brand Constraints Checklist

Non-negotiable rules enforced during build:

- [ ] No stock photography of physicians. No photography at all at launch.
- [ ] No blob gradients, mesh patterns, or AI-generated visuals.
- [ ] No emoji in any copy or UI element.
- [ ] No "AI" terminology anywhere on the site.
- [ ] No US statistics, US healthcare references, or generic healthcare content.
- [ ] No free trial messaging.
- [ ] No feature-gating UI.
- [ ] Minimise em dashes in all rendered copy.
- [ ] All prices in CAD. All prices exclude GST unless explicitly stated.
- [ ] Two typefaces maximum (Satoshi + IBM Plex Sans).
- [ ] No third typeface for any reason.

---

*End of specification. All decisions are final unless revisited. Copy source documents are the authority for page content; this spec is the authority for technical implementation, design system, and project structure.*
