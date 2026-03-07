// ============================================================================
// Provincial PHN Format Seed Data
// All 13 Canadian provinces and territories with PHN format definitions.
// Idempotent: safe to re-run.
// ============================================================================

import type { InsertProvincialPhnFormat } from '@meritum/shared/schemas/db/reference.schema.js';

export interface PhnFormatSeedEntry {
  provinceCode: string;
  provinceName: string;
  formatPattern: string;
  formatDescription: string;
  examplePhn: string;
  validationRegex: string;
  phnLength: number;
  isReciprocal: boolean;
}

/**
 * PHN format definitions for all Canadian provinces/territories.
 * Alberta is the home province; all others are out-of-province.
 * Quebec does NOT participate in reciprocal billing.
 *
 * Sources: Provincial ministry of health guidelines, CIHI standards.
 */
export const PROVINCIAL_PHN_FORMATS: PhnFormatSeedEntry[] = [
  {
    provinceCode: 'AB',
    provinceName: 'Alberta',
    formatPattern: '9999-99999',
    formatDescription: '9-digit numeric with optional dash after 4th digit. Validated with Luhn check digit.',
    examplePhn: '1234-56789',
    validationRegex: '^\\d{4}-?\\d{5}$',
    phnLength: 9,
    isReciprocal: false,
  },
  {
    provinceCode: 'BC',
    provinceName: 'British Columbia',
    formatPattern: '9999 999 999',
    formatDescription: '10-digit numeric. Personal Health Number (PHN) starting with 9.',
    examplePhn: '9876 543 210',
    validationRegex: '^9\\d{9}$',
    phnLength: 10,
    isReciprocal: true,
  },
  {
    provinceCode: 'SK',
    provinceName: 'Saskatchewan',
    formatPattern: '999 999 999',
    formatDescription: '9-digit numeric Health Services Number.',
    examplePhn: '123 456 789',
    validationRegex: '^\\d{9}$',
    phnLength: 9,
    isReciprocal: true,
  },
  {
    provinceCode: 'MB',
    provinceName: 'Manitoba',
    formatPattern: '999 999 999',
    formatDescription: '9-digit numeric Personal Health Identification Number (PHIN).',
    examplePhn: '123 456 789',
    validationRegex: '^\\d{9}$',
    phnLength: 9,
    isReciprocal: true,
  },
  {
    provinceCode: 'ON',
    provinceName: 'Ontario',
    formatPattern: '9999-999-999',
    formatDescription: '10-digit numeric OHIP number with format NNNN-NNN-NNN. May have 2-letter version code suffix.',
    examplePhn: '1234-567-890',
    validationRegex: '^\\d{4}-?\\d{3}-?\\d{3}([A-Z]{2})?$',
    phnLength: 10,
    isReciprocal: true,
  },
  {
    provinceCode: 'QC',
    provinceName: 'Quebec',
    formatPattern: 'AAAA 9999 9999',
    formatDescription: '12-character RAMQ number: 4 letters (first 3 of surname + first of given name) followed by 8 digits. Quebec does NOT participate in reciprocal billing.',
    examplePhn: 'SMIJ 8501 1234',
    validationRegex: '^[A-Z]{4}\\d{8}$',
    phnLength: 12,
    isReciprocal: false,
  },
  {
    provinceCode: 'NB',
    provinceName: 'New Brunswick',
    formatPattern: '999 999 999',
    formatDescription: '9-digit numeric Medicare number.',
    examplePhn: '123 456 789',
    validationRegex: '^\\d{9}$',
    phnLength: 9,
    isReciprocal: true,
  },
  {
    provinceCode: 'NS',
    provinceName: 'Nova Scotia',
    formatPattern: '9999 999 999',
    formatDescription: '10-digit numeric Health Card Number.',
    examplePhn: '1234 567 890',
    validationRegex: '^\\d{10}$',
    phnLength: 10,
    isReciprocal: true,
  },
  {
    provinceCode: 'PE',
    provinceName: 'Prince Edward Island',
    formatPattern: '99999999',
    formatDescription: '8-digit numeric Health Card Number.',
    examplePhn: '12345678',
    validationRegex: '^\\d{8}$',
    phnLength: 8,
    isReciprocal: true,
  },
  {
    provinceCode: 'NL',
    provinceName: 'Newfoundland and Labrador',
    formatPattern: '999 999 999 999',
    formatDescription: '12-digit numeric MCP (Medical Care Plan) number.',
    examplePhn: '123 456 789 012',
    validationRegex: '^\\d{12}$',
    phnLength: 12,
    isReciprocal: true,
  },
  {
    provinceCode: 'YT',
    provinceName: 'Yukon',
    formatPattern: '999 999 999',
    formatDescription: '9-digit numeric Health Care Insurance Plan number.',
    examplePhn: '123 456 789',
    validationRegex: '^\\d{9}$',
    phnLength: 9,
    isReciprocal: true,
  },
  {
    provinceCode: 'NT',
    provinceName: 'Northwest Territories',
    formatPattern: 'A9999999',
    formatDescription: '8-character: 1 letter prefix followed by 7 digits. NWT Health Care Card.',
    examplePhn: 'N1234567',
    validationRegex: '^[A-Z]\\d{7}$',
    phnLength: 8,
    isReciprocal: true,
  },
  {
    provinceCode: 'NU',
    provinceName: 'Nunavut',
    formatPattern: '999 999 999',
    formatDescription: '9-digit numeric Nunavut Health Care Plan number.',
    examplePhn: '123 456 789',
    validationRegex: '^\\d{9}$',
    phnLength: 9,
    isReciprocal: true,
  },
];

/**
 * Convert seed entries to Drizzle insert format.
 */
export function toInsertRecords(): InsertProvincialPhnFormat[] {
  return PROVINCIAL_PHN_FORMATS.map((entry) => ({
    provinceCode: entry.provinceCode,
    provinceName: entry.provinceName,
    phnLength: entry.phnLength,
    phnRegex: entry.validationRegex,
    validationAlgorithm: null,
    notes: entry.formatDescription,
  }));
}
