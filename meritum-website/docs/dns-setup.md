# Meritum DNS Setup — Cloudflare

## Prerequisites

- Domain `meritum.ca` registered and nameservers pointed to Cloudflare
- Cloudflare Pages project `meritum-website` created
- DigitalOcean droplet IP address for `app.meritum.ca` and `analytics.meritum.ca`

## DNS Records

| Type  | Name        | Value                            | Proxy   | Notes                        |
|-------|-------------|----------------------------------|---------|------------------------------|
| CNAME | `@`         | `meritum-website.pages.dev`      | Proxied | Marketing site (CF Pages)    |
| CNAME | `www`       | `meritum.ca`                     | Proxied | Redirects to root            |
| A     | `app`       | `<DO_DROPLET_IP>`                | Proxied | Application                  |
| A     | `analytics` | `<DO_DROPLET_IP>`                | Proxied | Plausible analytics          |

## Setup Steps

### 1. Add DNS records

In Cloudflare dashboard > DNS > Records:

1. Add CNAME record: Name `@`, Target `meritum-website.pages.dev`, Proxy status ON
2. Add CNAME record: Name `www`, Target `meritum.ca`, Proxy status ON
3. Add A record: Name `app`, Content `<DO_DROPLET_IP>`, Proxy status ON
4. Add A record: Name `analytics`, Content `<DO_DROPLET_IP>`, Proxy status ON

### 2. Configure WWW redirect

Cloudflare dashboard > Rules > Redirect Rules:

- Rule name: `www to root`
- When: Hostname equals `www.meritum.ca`
- Then: Dynamic redirect to `https://meritum.ca${http.request.uri.path}`
- Status code: 301

### 3. SSL/TLS configuration

Cloudflare dashboard > SSL/TLS:

- Encryption mode: **Full (strict)**
- Always Use HTTPS: ON
- Automatic HTTPS Rewrites: ON
- Minimum TLS Version: 1.2

### 4. Connect Cloudflare Pages

Cloudflare dashboard > Pages:

1. Create project: Connect to GitHub repo `meritum-website`
2. Build settings:
   - Framework preset: Astro
   - Build command: `pnpm build`
   - Build output directory: `dist`
3. Custom domain: Add `meritum.ca`
4. Production branch: `main`

### 5. Verification

```bash
# Verify DNS propagation
dig meritum.ca CNAME +short
dig app.meritum.ca A +short
dig analytics.meritum.ca A +short

# Verify HTTPS
curl -I https://meritum.ca
curl -I https://www.meritum.ca  # Should 301 to root

# Verify Cloudflare Pages
curl -I https://meritum.ca | grep cf-cache-status
```

## Email (Future)

When a mail provider is selected (Postmark recommended):

| Type | Name | Value           | Proxy    |
|------|------|-----------------|----------|
| MX   | `@`  | Provider MX     | DNS only |
| TXT  | `@`  | SPF record      | DNS only |
| TXT  | `_dmarc` | DMARC record | DNS only |
| CNAME | Provider-specific | DKIM | DNS only |
