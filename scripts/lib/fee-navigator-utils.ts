// ============================================================================
// Shared utilities for Fee Navigator scraper and enrichment scripts.
// Extracted from scrape-fee-navigator.ts and enrich-hsc-data.ts (SCR-001).
// Hardened with AbortController timeout, entity decoding, CAPTCHA detection (SCR-002).
// ============================================================================

import * as fs from 'node:fs';
import * as path from 'node:path';

// ============================================================================
// Constants
// ============================================================================

export const BASE_URL = 'https://apps.albertadoctors.org/fee-navigator';
export const DELAY_MS = 200;
export const MAX_RETRIES = 3;

export const HEADERS: Record<string, string> = {
  'User-Agent':
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
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
  const lower = body.slice(0, 2000).toLowerCase();
  if (
    lower.includes('captcha') ||
    lower.includes('access denied') ||
    lower.includes('rate limit exceeded') ||
    lower.includes('too many requests')
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
      clearTimeout(timer);

      if (resp.status === 429 || resp.status === 503) {
        const backoff = Math.pow(2, attempt) * 1000;
        console.warn(
          `  [RETRY] ${resp.status} on ${url} — waiting ${backoff}ms (attempt ${attempt}/${retries})`,
        );
        await sleep(backoff);
        continue;
      }
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      const body = await resp.text();
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
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  console.log(`  Saved ${filePath}`);
}

export function loadJson<T>(outputDir: string, filename: string): T | null {
  const filePath = path.join(outputDir, filename);
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  }
  return null;
}
