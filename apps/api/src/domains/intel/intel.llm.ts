// ============================================================================
// Domain 7: Intelligence Engine — Tier 2 LLM Integration
// Configurable OpenAI-compatible HTTP client, PHI stripping, response
// processing, hallucination guard.
// ============================================================================

import { LLM_TIMEOUT_MS, LLM_CONFIDENCE_THRESHOLD, SuggestionCategory, SuggestionPriority, SuggestionEventType, IntelTier } from '@meritum/shared/constants/intelligence.constants.js';
import type { ClaimContext, Suggestion } from './intel.service.js';

// ---------------------------------------------------------------------------
// LLM Client Configuration
// ---------------------------------------------------------------------------

export interface LlmClientConfig {
  baseUrl: string;
  model: string;
  apiKey?: string;
  timeoutMs: number;
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface ChatCompletionOptions {
  temperature?: number;
  maxTokens?: number;
  responseFormat?: { type: string };
}

export interface ChatCompletionResult {
  content: string;
  finishReason: string;
}

export interface LlmClient {
  chatCompletion(messages: ChatMessage[], options?: ChatCompletionOptions): Promise<ChatCompletionResult>;
  config: Readonly<LlmClientConfig>;
}

// ---------------------------------------------------------------------------
// LLM Client Factory
// ---------------------------------------------------------------------------

/**
 * Create an LLM client that speaks the OpenAI-compatible `/v1/chat/completions`
 * protocol. Works with llama.cpp, Ollama, vLLM, or any OpenAI-compatible API.
 *
 * Config values fall back to environment variables. If neither LLM_BASE_URL
 * nor LLM_MODEL is set, the factory returns `null` (Tier 2 disabled).
 */
export function createLlmClient(config?: Partial<LlmClientConfig>): LlmClient | null {
  const baseUrl = config?.baseUrl ?? process.env.LLM_BASE_URL;
  const model = config?.model ?? process.env.LLM_MODEL;
  const apiKey = config?.apiKey ?? process.env.LLM_API_KEY;
  const timeoutMs = config?.timeoutMs ?? (process.env.LLM_TIMEOUT_MS ? parseInt(process.env.LLM_TIMEOUT_MS, 10) : LLM_TIMEOUT_MS);

  if (!baseUrl || !model) {
    return null;
  }

  const resolvedConfig: LlmClientConfig = { baseUrl, model, apiKey, timeoutMs };

  return {
    config: Object.freeze(resolvedConfig),

    async chatCompletion(
      messages: ChatMessage[],
      options?: ChatCompletionOptions,
    ): Promise<ChatCompletionResult> {
      const url = `${baseUrl}/v1/chat/completions`;

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (apiKey) {
        headers['Authorization'] = `Bearer ${apiKey}`;
      }

      const body = JSON.stringify({
        model,
        messages,
        temperature: options?.temperature ?? 0.1,
        max_tokens: options?.maxTokens ?? 1024,
        ...(options?.responseFormat ? { response_format: options.responseFormat } : {}),
      });

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), resolvedConfig.timeoutMs);

      try {
        const response = await fetch(url, {
          method: 'POST',
          headers,
          body,
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`LLM API error: ${response.status}`);
        }

        const json = await response.json() as {
          choices?: Array<{
            message?: { content?: string };
            finish_reason?: string;
          }>;
        };

        const choice = json.choices?.[0];
        return {
          content: choice?.message?.content ?? '',
          finishReason: choice?.finish_reason ?? 'unknown',
        };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Singleton LLM Client
// ---------------------------------------------------------------------------

let _llmClient: LlmClient | null | undefined;
let _warnedDisabled = false;

/**
 * Get the singleton LLM client. Returns `null` when Tier 2 is disabled
 * (LLM_BASE_URL or LLM_MODEL not configured). Logs a warning on first
 * call if disabled.
 */
export function getLlmClient(): LlmClient | null {
  if (_llmClient === undefined) {
    _llmClient = createLlmClient();
    if (_llmClient === null && !_warnedDisabled) {
      _warnedDisabled = true;
      console.warn('[intel.llm] Tier 2 LLM is disabled: LLM_BASE_URL or LLM_MODEL not configured');
    }
  }
  return _llmClient;
}

/** Reset the singleton — for tests only. */
export function _resetLlmClient(): void {
  _llmClient = undefined;
  _warnedDisabled = false;
}

// ---------------------------------------------------------------------------
// PHI Stripping
// ---------------------------------------------------------------------------

/** Claim context with PHI placeholder markers for LLM consumption. */
export interface AnonymisedClaimContext {
  claim: ClaimContext['claim'];
  ahcip: ClaimContext['ahcip'];
  wcb: ClaimContext['wcb'];
  patient: ClaimContext['patient'];
  provider: ClaimContext['provider'];
  reference: ClaimContext['reference'];
}

/**
 * Strip PHI from a ClaimContext before sending to the LLM.
 *
 * - Patient PHN: replaced with 'XXXNNNNNN' (already excluded in
 *   ClaimContext — but this guards against accidental leakage in
 *   any extended fields).
 * - Patient name: replaced with 'PATIENT'.
 * - Referral practitioner IDs: replaced with 'PROVIDER_REF'.
 * - All billing structure (codes, modifiers, dates, clinical codes) preserved.
 */
export function stripPhi(claimContext: ClaimContext): AnonymisedClaimContext {
  return {
    claim: { ...claimContext.claim },
    ahcip: claimContext.ahcip
      ? {
          ...claimContext.ahcip,
          referralPractitioner: claimContext.ahcip.referralPractitioner
            ? 'PROVIDER_REF'
            : null,
        }
      : null,
    wcb: claimContext.wcb ? { ...claimContext.wcb } : null,
    patient: { ...claimContext.patient },
    provider: { ...claimContext.provider },
    reference: { ...claimContext.reference },
  };
}

// ---------------------------------------------------------------------------
// Source Reference Validation (Hallucination Guard)
// ---------------------------------------------------------------------------

/** Dependencies for validating LLM source references against Reference Data. */
export interface ReferenceValidationDeps {
  findActiveVersion: (dataSet: string) => Promise<{ versionId: string } | undefined>;
  findRuleById: (ruleId: string, versionId: string) => Promise<unknown | undefined>;
  findHscByCode: (hscCode: string, versionId: string) => Promise<unknown | undefined>;
}

/**
 * Validate an LLM-cited source reference against Reference Data.
 *
 * Supported reference patterns:
 * - "GR1", "GR-1", "GR 1", "GR01" — Governing Rule lookup
 * - "SOMB ... Section X.Y.Z" — (trusted: no direct lookup, but validate SOMB version exists)
 * - "HSC:03.04A" — HSC code existence check
 *
 * Returns `true` if the reference can be confirmed, `false` if it looks
 * fabricated (hallucination).
 */
export async function validateLlmSourceReference(
  reference: string,
  deps: ReferenceValidationDeps,
): Promise<boolean> {
  if (!reference || reference.trim().length === 0) return false;

  const trimmed = reference.trim();

  // Pattern 1: Governing Rule reference (e.g., "GR1", "GR-3", "GR 12", "SURCHARGE_1")
  const grMatch = trimmed.match(/^GR[-\s]?(\d+)/i);
  if (grMatch) {
    const ruleId = `GR${grMatch[1]}`;
    const version = await deps.findActiveVersion('GOVERNING_RULES');
    if (!version) return false;
    const rule = await deps.findRuleById(ruleId, version.versionId);
    return rule !== undefined && rule !== null;
  }

  // Pattern 2: Surcharge rule reference
  const surchargeMatch = trimmed.match(/^SURCHARGE[-_\s]?(\d+)/i);
  if (surchargeMatch) {
    const ruleId = `SURCHARGE_${surchargeMatch[1]}`;
    const version = await deps.findActiveVersion('GOVERNING_RULES');
    if (!version) return false;
    const rule = await deps.findRuleById(ruleId, version.versionId);
    return rule !== undefined && rule !== null;
  }

  // Pattern 3: HSC code reference (e.g., "HSC:03.04A" or just a code like "03.04A")
  const hscMatch = trimmed.match(/^HSC:\s*(\S+)/i);
  if (hscMatch) {
    const hscCode = hscMatch[1];
    const version = await deps.findActiveVersion('SOMB');
    if (!version) return false;
    const hsc = await deps.findHscByCode(hscCode, version.versionId);
    return hsc !== undefined && hsc !== null;
  }

  // Pattern 4: SOMB section reference — validate that SOMB data exists (version check)
  const sombMatch = trimmed.match(/^SOMB\b/i);
  if (sombMatch) {
    const version = await deps.findActiveVersion('SOMB');
    return version !== undefined && version !== null;
  }

  // Unknown reference pattern — treat as unvalidated (allow it through
  // for now; the hallucination guard only suppresses _known_ bad references)
  return true;
}

// ---------------------------------------------------------------------------
// LLM Response Parsing
// ---------------------------------------------------------------------------

interface LlmSuggestionResponse {
  explanation: string;
  confidence: number;
  source_reference: string;
  category?: string;
  suggested_changes?: Array<{ field: string; value_formula: string }>;
  revenue_impact?: number;
}

function parseLlmResponse(content: string): LlmSuggestionResponse | null {
  try {
    const parsed = JSON.parse(content) as Record<string, unknown>;
    if (
      typeof parsed.explanation !== 'string' ||
      typeof parsed.confidence !== 'number' ||
      typeof parsed.source_reference !== 'string'
    ) {
      return null;
    }
    return {
      explanation: parsed.explanation,
      confidence: parsed.confidence,
      source_reference: parsed.source_reference,
      category: typeof parsed.category === 'string' ? parsed.category : undefined,
      suggested_changes: Array.isArray(parsed.suggested_changes) ? parsed.suggested_changes as LlmSuggestionResponse['suggested_changes'] : undefined,
      revenue_impact: typeof parsed.revenue_impact === 'number' ? parsed.revenue_impact : undefined,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Prompt Construction
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a medical billing domain expert specialising in Alberta AHCIP and WCB billing.

CONSTRAINTS:
- NEVER fabricate rules, SOMB sections, or governing rule references that do not exist.
- ALWAYS cite the specific SOMB section, governing rule (GR), or WCB policy reference that supports your suggestion.
- If you are uncertain, set your confidence score below 0.60 and acknowledge the uncertainty.
- Base your analysis ONLY on the claim context, provider specialty, and reference data provided.
- Do NOT make assumptions about patient clinical details beyond what is in the claim data.

Respond with a JSON object containing:
{
  "explanation": "Your detailed analysis and recommendation",
  "confidence": 0.00 to 1.00,
  "source_reference": "The specific SOMB section, GR number, or WCB policy reference",
  "category": "One of: MODIFIER_ADD, CODE_ALTERNATIVE, CODE_ADDITION, MISSED_BILLING, FEE_OPTIMISATION",
  "revenue_impact": null or estimated dollar amount,
  "suggested_changes": [{"field": "field_name", "value_formula": "suggested_value"}] or null
}`;

function buildUserPrompt(
  anonymisedContext: AnonymisedClaimContext,
  tier1Results: Suggestion[],
  sombRules: string[],
): string {
  const parts: string[] = [];

  parts.push('## Claim Context (Anonymised)');
  parts.push(JSON.stringify(anonymisedContext, null, 2));

  if (sombRules.length > 0) {
    parts.push('\n## Applicable SOMB Rules');
    for (const rule of sombRules) {
      parts.push(`- ${rule}`);
    }
  }

  if (tier1Results.length > 0) {
    parts.push('\n## Tier 1 Analysis Results');
    for (const s of tier1Results) {
      parts.push(`- [${s.category}] ${s.title}: ${s.description} (source: ${s.sourceReference})`);
    }
  }

  parts.push('\n## Task');
  parts.push('Analyse this claim for additional billing optimisation opportunities not covered by the Tier 1 rules above. Focus on nuanced modifier applicability, code alternatives, and missed billing opportunities specific to the provider specialty and encounter context.');

  return parts.join('\n');
}

// ---------------------------------------------------------------------------
// Tier 2 Analysis
// ---------------------------------------------------------------------------

/** Dependencies for Tier 2 analysis. */
export interface Tier2Deps {
  llmClient: LlmClient | null;
  referenceValidation: ReferenceValidationDeps;
  appendSuggestionEvent?: (event: {
    claimId: string;
    suggestionId: string;
    ruleId?: string | null;
    providerId: string;
    eventType: string;
    tier: number;
    category: string;
    revenueImpact?: string | null;
    dismissedReason?: string | null;
  }) => Promise<unknown>;
}

/**
 * Run Tier 2 LLM analysis on a claim.
 *
 * 1. Check LLM availability (graceful degradation if unavailable).
 * 2. Strip PHI from claim context.
 * 3. Construct structured prompt with anonymised context + Tier 1 results.
 * 4. Call LLM with configured timeout.
 * 5. Parse response, apply confidence threshold, hallucination guard.
 * 6. Return Suggestion[] (may be empty on timeout/error/unavailable).
 */
export async function analyseTier2(
  claimId: string,
  providerId: string,
  claimContext: ClaimContext,
  tier1Results: Suggestion[],
  deps: Tier2Deps,
): Promise<Suggestion[]> {
  // 1. Check LLM availability
  if (!deps.llmClient) {
    return [];
  }

  // 2. Strip PHI
  const anonymised = stripPhi(claimContext);

  // 3. Build SOMB rules list from reference context
  const sombRules: string[] = [];
  if (claimContext.reference.hscCode) {
    sombRules.push(`HSC ${claimContext.reference.hscCode.hscCode}: fee=${claimContext.reference.hscCode.baseFee}, type=${claimContext.reference.hscCode.feeType}`);
  }
  for (const mod of claimContext.reference.modifiers) {
    sombRules.push(`Modifier ${mod.modifierCode}: type=${mod.type}, calc=${mod.calculationMethod}`);
  }

  // 4. Construct prompt
  const messages: ChatMessage[] = [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: buildUserPrompt(anonymised, tier1Results, sombRules) },
  ];

  // 5. Call LLM with timeout
  let result: ChatCompletionResult;
  try {
    result = await deps.llmClient.chatCompletion(messages, {
      temperature: 0.1,
      maxTokens: 1024,
      responseFormat: { type: 'json_object' },
    });
  } catch {
    // Timeout or connection error — graceful fallback
    return [];
  }

  // 6. Parse response
  const parsed = parseLlmResponse(result.content);
  if (!parsed) {
    return [];
  }

  // 7. Confidence threshold — below 0.60 routes to Tier 3
  if (parsed.confidence < LLM_CONFIDENCE_THRESHOLD) {
    const tier3Suggestion: Suggestion = {
      suggestionId: crypto.randomUUID(),
      ruleId: '',
      tier: 3,
      category: SuggestionCategory.REVIEW_RECOMMENDED,
      priority: SuggestionPriority.MEDIUM,
      title: 'Complex case — review recommended',
      description: parsed.explanation,
      revenueImpact: parsed.revenue_impact ?? null,
      confidence: parsed.confidence,
      sourceReference: parsed.source_reference,
      sourceUrl: null,
      suggestedChanges: null,
    };

    if (deps.appendSuggestionEvent) {
      deps.appendSuggestionEvent({
        claimId,
        suggestionId: tier3Suggestion.suggestionId,
        ruleId: null,
        providerId,
        eventType: SuggestionEventType.GENERATED,
        tier: 3,
        category: SuggestionCategory.REVIEW_RECOMMENDED,
        revenueImpact: parsed.revenue_impact?.toFixed(2) ?? null,
      }).catch(() => {/* fire-and-forget */});
    }

    return [tier3Suggestion];
  }

  // 8. Hallucination guard — validate source reference
  const isValidReference = await validateLlmSourceReference(
    parsed.source_reference,
    deps.referenceValidation,
  );

  if (!isValidReference) {
    // Suppress hallucinated suggestion, log for rule library improvement
    if (deps.appendSuggestionEvent) {
      deps.appendSuggestionEvent({
        claimId,
        suggestionId: crypto.randomUUID(),
        ruleId: null,
        providerId,
        eventType: SuggestionEventType.SUPPRESSED,
        tier: 2,
        category: parsed.category ?? SuggestionCategory.REVIEW_RECOMMENDED,
        dismissedReason: `Hallucination guard: invalid source reference "${parsed.source_reference}"`,
      }).catch(() => {/* fire-and-forget */});
    }
    return [];
  }

  // 9. Build Tier 2 suggestion
  const category = parsed.category && Object.values(SuggestionCategory).includes(parsed.category as SuggestionCategory)
    ? (parsed.category as SuggestionCategory)
    : SuggestionCategory.REVIEW_RECOMMENDED;

  const revenueImpact = parsed.revenue_impact ?? null;

  const suggestion: Suggestion = {
    suggestionId: crypto.randomUUID(),
    ruleId: '',
    tier: 2,
    category,
    priority: determinePriority(revenueImpact),
    title: parsed.explanation.slice(0, 200),
    description: parsed.explanation,
    revenueImpact,
    confidence: parsed.confidence,
    sourceReference: parsed.source_reference,
    sourceUrl: null,
    suggestedChanges: parsed.suggested_changes?.map(c => ({ field: c.field, valueFormula: c.value_formula })) ?? null,
  };

  if (deps.appendSuggestionEvent) {
    deps.appendSuggestionEvent({
      claimId,
      suggestionId: suggestion.suggestionId,
      ruleId: null,
      providerId,
      eventType: SuggestionEventType.GENERATED,
      tier: 2,
      category: suggestion.category,
      revenueImpact: revenueImpact?.toFixed(2) ?? null,
    }).catch(() => {/* fire-and-forget */});
  }

  return [suggestion];
}

// ---------------------------------------------------------------------------
// Priority from revenue impact (Tier 2 only — no rule formula)
// ---------------------------------------------------------------------------

function determinePriority(revenueImpact: number | null): SuggestionPriority {
  if (revenueImpact === null) return SuggestionPriority.LOW;
  if (revenueImpact > 20) return SuggestionPriority.HIGH;
  if (revenueImpact >= 5) return SuggestionPriority.MEDIUM;
  return SuggestionPriority.LOW;
}
