// ============================================================================
// Domain 2: Reference Data — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import { ReferenceDataSet } from '../constants/reference.constants.js';

const DATA_SET_VALUES = Object.values(ReferenceDataSet) as [string, ...string[]];

// --- HSC Search ---

export const hscSearchSchema = z.object({
  q: z.string().min(1).max(100),
  specialty: z.string().optional(),
  facility: z.string().optional(),
  date: z.string().date().optional(),
  limit: z.coerce.number().int().min(1).max(50).default(10),
});

export type HscSearch = z.infer<typeof hscSearchSchema>;

// --- HSC Detail ---

export const hscDetailParamSchema = z.object({
  code: z.string().max(10),
});

export type HscDetailParam = z.infer<typeof hscDetailParamSchema>;

export const hscDetailQuerySchema = z.object({
  date: z.string().date().optional(),
});

export type HscDetailQuery = z.infer<typeof hscDetailQuerySchema>;

// --- DI Search ---

export const diSearchSchema = z.object({
  q: z.string().min(1).max(100),
  specialty: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(50).default(10),
});

export type DiSearch = z.infer<typeof diSearchSchema>;

// --- DI Detail ---

export const diDetailParamSchema = z.object({
  code: z.string().max(10),
});

export type DiDetailParam = z.infer<typeof diDetailParamSchema>;

// --- Modifier Lookup ---

export const modifierLookupSchema = z.object({
  hsc: z.string().max(10).optional(),
  date: z.string().date().optional(),
});

export type ModifierLookup = z.infer<typeof modifierLookupSchema>;

// --- Modifier Detail ---

export const modifierDetailParamSchema = z.object({
  code: z.string().max(10),
});

export type ModifierDetailParam = z.infer<typeof modifierDetailParamSchema>;

// --- Functional Centres ---

export const fcListSchema = z.object({
  facility_type: z.string().optional(),
});

export type FcList = z.infer<typeof fcListSchema>;

// --- Explanatory Code ---

export const explCodeParamSchema = z.object({
  code: z.string().max(10),
});

export type ExplCodeParam = z.infer<typeof explCodeParamSchema>;

// --- RRNP Lookup ---

export const rrnpLookupSchema = z.object({
  date: z.string().date().optional(),
});

export type RrnpLookup = z.infer<typeof rrnpLookupSchema>;

export const rrnpParamSchema = z.object({
  community_id: z.string().uuid(),
});

export type RrnpParam = z.infer<typeof rrnpParamSchema>;

// --- PCPCM Lookup ---

export const pcpcmLookupSchema = z.object({
  date: z.string().date().optional(),
});

export type PcpcmLookup = z.infer<typeof pcpcmLookupSchema>;

export const pcpcmParamSchema = z.object({
  hsc_code: z.string().max(10),
});

export type PcpcmParam = z.infer<typeof pcpcmParamSchema>;

// --- Holiday List ---

export const holidayListSchema = z.object({
  year: z.coerce.number().int().min(2020).max(2100),
});

export type HolidayList = z.infer<typeof holidayListSchema>;

// --- Holiday Check ---

export const holidayCheckSchema = z.object({
  date: z.string().date(),
});

export type HolidayCheck = z.infer<typeof holidayCheckSchema>;

// --- Change Summaries ---

export const changeListSchema = z.object({
  dataset: z.string().optional(),
  since: z.string().date().optional(),
});

export type ChangeList = z.infer<typeof changeListSchema>;

// --- Change Detail ---

export const changeDetailParamSchema = z.object({
  version_id: z.string().uuid(),
});

export type ChangeDetailParam = z.infer<typeof changeDetailParamSchema>;

export const changeDetailQuerySchema = z.object({
  specialty: z.string().optional(),
});

export type ChangeDetailQuery = z.infer<typeof changeDetailQuerySchema>;

// --- Admin Upload ---

export const adminUploadParamSchema = z.object({
  dataset: z.enum(DATA_SET_VALUES),
});

export type AdminUploadParam = z.infer<typeof adminUploadParamSchema>;

// --- Admin Staging ---

export const adminStagingParamSchema = z.object({
  dataset: z.enum(DATA_SET_VALUES),
  id: z.string().uuid(),
});

export type AdminStagingParam = z.infer<typeof adminStagingParamSchema>;

// --- Admin Publish ---

export const adminPublishSchema = z.object({
  version_label: z.string().min(1).max(50),
  effective_from: z.string().date(),
  source_document: z.string().optional(),
  change_summary: z.string().optional(),
});

export type AdminPublish = z.infer<typeof adminPublishSchema>;

// --- Admin Version List ---

export const adminVersionListSchema = z.object({
  dataset: z.enum(DATA_SET_VALUES),
});

export type AdminVersionList = z.infer<typeof adminVersionListSchema>;

// --- Admin Holidays ---

export const createHolidaySchema = z.object({
  date: z.string().date(),
  name: z.string().min(1).max(100),
  jurisdiction: z.enum(['provincial', 'federal', 'both']),
  affects_billing_premiums: z.boolean().default(true),
});

export type CreateHoliday = z.infer<typeof createHolidaySchema>;

export const updateHolidaySchema = z.object({
  date: z.string().date().optional(),
  name: z.string().min(1).max(100).optional(),
  jurisdiction: z.enum(['provincial', 'federal', 'both']).optional(),
  affects_billing_premiums: z.boolean().optional(),
});

export type UpdateHoliday = z.infer<typeof updateHolidaySchema>;

export const holidayParamSchema = z.object({
  id: z.string().uuid(),
});

export type HolidayParam = z.infer<typeof holidayParamSchema>;

// --- Admin Dry-Run ---

export const dryRunSchema = z.object({
  updated_rule_logic: z.object({}).passthrough(),
});

export type DryRun = z.infer<typeof dryRunSchema>;

export const dryRunParamSchema = z.object({
  rule_id: z.string().max(20),
});

export type DryRunParam = z.infer<typeof dryRunParamSchema>;

// --- Internal Validation: Validate Context ---

// Query strings may send a single value or repeated values for array params.
// Preprocess to normalise single values into arrays.
const coerceStringArray = z.preprocess(
  (val) => (typeof val === 'string' ? [val] : val),
  z.array(z.string()),
);

export const validateContextSchema = z.object({
  hsc: coerceStringArray.pipe(z.array(z.string()).min(1)),
  di: z.string().optional(),
  facility: z.string().optional(),
  date: z.string().date(),
  modifiers: coerceStringArray.optional(),
});

export type ValidateContext = z.infer<typeof validateContextSchema>;

// --- Internal Validation: Evaluate Batch ---

export const evaluateBatchSchema = z.object({
  claims: z.array(z.object({}).passthrough()).min(1).max(500),
});

export type EvaluateBatch = z.infer<typeof evaluateBatchSchema>;

// --- Internal Validation: Rule Detail ---

export const ruleDetailSchema = z.object({
  rule_id: z.string().max(20),
});

export type RuleDetail = z.infer<typeof ruleDetailSchema>;

export const ruleDetailQuerySchema = z.object({
  date: z.string().date().optional(),
});

export type RuleDetailQuery = z.infer<typeof ruleDetailQuerySchema>;

// --- Internal Validation: Version Query ---

export const versionQuerySchema = z.object({
  date: z.string().date(),
});

export type VersionQuery = z.infer<typeof versionQuerySchema>;
