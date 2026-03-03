// ============================================================================
// Shared utilities for Fee Navigator scraper and enrichment scripts.
// Extracted from scrape-fee-navigator.ts and enrich-hsc-data.ts (SCR-001).
// Hardened with AbortController timeout, entity decoding, CAPTCHA detection (SCR-002).
// ============================================================================

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// ============================================================================
// Constants
// ============================================================================

export const BASE_URL = 'https://apps.albertadoctors.org/fee-navigator';
export const DELAY_MS = 200;
export const MAX_RETRIES = 3;

export const STEALTH_MODE = process.argv.includes('--stealth');

export const HEADERS: Record<string, string> = {
  'User-Agent': STEALTH_MODE
    ? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    : 'Meritum-SOMB-Scraper/1.0 (+https://meritum.ca; contact@meritum.ca)',
  Referer: `${BASE_URL}/hsc`,
  'X-Requested-With': 'XMLHttpRequest',
};

// ============================================================================
// Utility Functions
// ============================================================================

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function validateResponse(url: string, body: string): void {
  // AJAX responses should contain XML <content> wrapper
  if (url.includes('?ajax=')) {
    if (!body.includes('<content>') && body.trim().length > 0) {
      throw new Error(
        `Invalid AJAX response from ${url}: missing <content> wrapper (possible CAPTCHA or error page). ` +
        `Response starts with: ${body.slice(0, 200)}`,
      );
    }
  }

  // Check for common block/CAPTCHA indicators
  const lower = body.slice(0, 5000).toLowerCase();
  if (
    lower.includes('captcha') ||
    lower.includes('access denied') ||
    lower.includes('rate limit exceeded') ||
    lower.includes('too many requests') ||
    lower.includes('you have been blocked') ||
    lower.includes('your ip has been blocked') ||
    lower.includes('access has been blocked') ||
    lower.includes('your access is blocked') ||
    lower.includes('cloudflare') ||
    lower.includes('please verify you are human')
  ) {
    throw new Error(
      `Possible block detected from ${url}: response contains block indicators. ` +
      `Response starts with: ${body.slice(0, 200)}`,
    );
  }
}

export async function fetchWithRetry(
  url: string,
  options: RequestInit = {},
  retries = MAX_RETRIES,
  timeoutMs = 30_000,
): Promise<string> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: { ...HEADERS, ...(options.headers as Record<string, string>) },
      });
      // Don't clearTimeout here — body may still be streaming

      if (resp.status === 429 || resp.status === 503) {
        clearTimeout(timer);
        const backoff = Math.pow(2, attempt) * 1000;
        console.warn(
          `  [RETRY] ${resp.status} on ${url} — waiting ${backoff}ms (attempt ${attempt}/${retries})`,
        );
        await sleep(backoff);
        continue;
      }
      if (!resp.ok) {
        clearTimeout(timer);
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      const body = await resp.text(); // Timer still running — abort on body stall
      clearTimeout(timer); // NOW safe to clear
      validateResponse(url, body);
      return body;
    } catch (err) {
      clearTimeout(timer);
      if ((err as Error).name === 'AbortError') {
        console.warn(`  [TIMEOUT] ${url} after ${timeoutMs}ms (attempt ${attempt}/${retries})`);
        if (attempt === retries) throw new Error(`Timeout after ${retries} retries: ${url}`);
        await sleep(Math.pow(2, attempt) * 1000);
        continue;
      }
      if (attempt === retries) throw err;
      const backoff = Math.pow(2, attempt) * 1000;
      console.warn(
        `  [RETRY] Error on ${url}: ${(err as Error).message} — waiting ${backoff}ms (attempt ${attempt}/${retries})`,
      );
      await sleep(backoff);
    }
  }
  throw new Error(`Failed after ${retries} retries: ${url}`);
}

export function decodeHtmlEntities(xml: string): string {
  const contentMatch = xml.match(/<content>([\s\S]*?)<\/content>/);
  if (!contentMatch) return '';
  return contentMatch[1]
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, '\u00A0')
    .replace(/&ndash;/g, '\u2013')
    .replace(/&mdash;/g, '\u2014')
    .replace(/&rsquo;/g, '\u2019')
    .replace(/&lsquo;/g, '\u2018')
    .replace(/&rdquo;/g, '\u201D')
    .replace(/&ldquo;/g, '\u201C')
    .replace(/&hellip;/g, '\u2026')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&amp;/g, '&'); // MUST be last — earlier replacements may produce & chars
}

export function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export function saveJson(outputDir: string, filename: string, data: unknown): void {
  ensureDir(outputDir);
  const filePath = path.join(outputDir, filename);
  const tmpPath = filePath + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2));
  fs.renameSync(tmpPath, filePath);  // atomic on same filesystem
  console.log(`  Saved ${filePath}`);
}

export function loadJson<T>(outputDir: string, filename: string): T | null {
  const filePath = path.join(outputDir, filename);
  if (fs.existsSync(filePath)) {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch (err) {
      console.warn(`  [WARN] Could not parse ${filePath}: ${(err as Error).message}`);
      return null;
    }
  }
  return null;
}

/**
 * Check robots.txt for the target host. Returns an object indicating
 * whether scraping is allowed and any crawl-delay.
 */
export async function checkRobotsTxt(baseUrl: string): Promise<{
  allowed: boolean;
  crawlDelay: number | null;
  raw: string | null;
}> {
  const url = new URL(baseUrl);
  const robotsUrl = `${url.protocol}//${url.host}/robots.txt`;

  try {
    const resp = await fetch(robotsUrl, {
      headers: { 'User-Agent': HEADERS['User-Agent'] },
    });

    if (resp.status === 404) {
      // No robots.txt — everything is allowed
      return { allowed: true, crawlDelay: null, raw: null };
    }

    if (!resp.ok) {
      console.warn(`  [WARN] robots.txt returned HTTP ${resp.status} — proceeding with caution`);
      return { allowed: true, crawlDelay: null, raw: null };
    }

    const body = await resp.text();

    // Parse for our user-agent or wildcard
    const lines = body.split('\n').map(l => l.trim().toLowerCase());
    let inOurSection = false;
    let inWildcard = false;
    let disallowed = false;
    let crawlDelay: number | null = null;

    for (const line of lines) {
      if (line.startsWith('user-agent:')) {
        const ua = line.replace('user-agent:', '').trim();
        inOurSection = ua === 'meritum-somb-scraper' || ua === 'meritum';
        inWildcard = ua === '*';
      } else if (inOurSection || inWildcard) {
        if (line.startsWith('disallow:')) {
          const path = line.replace('disallow:', '').trim();
          // Check if our target paths are disallowed
          if (path === '/' || path === '/fee-navigator' || path === '/fee-navigator/') {
            disallowed = true;
          }
        }
        if (line.startsWith('crawl-delay:')) {
          const delay = parseFloat(line.replace('crawl-delay:', '').trim());
          if (!isNaN(delay)) crawlDelay = delay;
        }
      }
    }

    // Our specific UA section takes precedence over wildcard
    return { allowed: !disallowed, crawlDelay, raw: body };
  } catch (err) {
    console.warn(`  [WARN] Could not fetch robots.txt: ${(err as Error).message} — proceeding`);
    return { allowed: true, crawlDelay: null, raw: null };
  }
}

/** Compute SHA-256 hash of a file's contents */
export function computeFileHash(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}
