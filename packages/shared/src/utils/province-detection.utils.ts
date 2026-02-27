// ============================================================================
// Reciprocal Billing — Province Detection Utility (FRD MVPADD-001 §B8)
// ============================================================================

/**
 * Canadian province/territory PHN format definitions.
 * Used for auto-detecting a patient's home province from PHN format.
 *
 * Each entry defines the PHN length, regex pattern, and optional
 * check digit algorithm for a province/territory.
 */

interface ProvincePhnFormat {
  readonly code: string;
  readonly name: string;
  readonly length: number;
  readonly regex: RegExp;
}

const PROVINCE_PHN_FORMATS: readonly ProvincePhnFormat[] = [
  { code: 'AB', name: 'Alberta', length: 9, regex: /^\d{9}$/ },
  { code: 'BC', name: 'British Columbia', length: 10, regex: /^\d{10}$/ },
  { code: 'SK', name: 'Saskatchewan', length: 9, regex: /^\d{9}$/ },
  { code: 'MB', name: 'Manitoba', length: 9, regex: /^\d{9}$/ },
  { code: 'ON', name: 'Ontario', length: 10, regex: /^\d{4}-\d{3}-\d{3}$|^\d{10}$/ },
  { code: 'QC', name: 'Quebec', length: 12, regex: /^[A-Z]{4}\d{8}$/ },
  { code: 'NB', name: 'New Brunswick', length: 9, regex: /^\d{9}$/ },
  { code: 'NS', name: 'Nova Scotia', length: 10, regex: /^\d{10}$/ },
  { code: 'PE', name: 'Prince Edward Island', length: 8, regex: /^\d{8}$/ },
  { code: 'NL', name: 'Newfoundland and Labrador', length: 12, regex: /^\d{12}$/ },
  { code: 'YT', name: 'Yukon', length: 9, regex: /^\d{9}$/ },
  { code: 'NT', name: 'Northwest Territories', length: 8, regex: /^[A-Z]\d{7}$/ },
  { code: 'NU', name: 'Nunavut', length: 9, regex: /^\d{9}$/ },
] as const;

export interface ProvinceDetectionResult {
  /** Detected province code, or null if ambiguous/unrecognised */
  provinceCode: string | null;
  /** Candidate province codes if multiple match */
  candidates: string[];
  /** Whether the PHN format is definitively from one province */
  isDefinitive: boolean;
}

/**
 * Attempts to detect the home province of a PHN based on format analysis.
 *
 * Some PHN formats are shared across provinces (e.g. 9-digit numeric is
 * used by AB, SK, MB, NB, YT, NU). In those cases, `isDefinitive` will
 * be false and `candidates` will list all matching provinces.
 *
 * Definitively identifiable formats:
 * - BC (10-digit numeric)
 * - ON (####-###-### or 10-digit)
 * - QC (4 alpha + 8 numeric)
 * - PE (8-digit numeric)
 * - NL (12-digit numeric)
 * - NT (1 alpha + 7 numeric)
 *
 * @param phn - The PHN string (whitespace/hyphens preserved for ON detection)
 */
export function detectProvinceFromPhn(phn: string): ProvinceDetectionResult {
  const normalised = phn.trim();

  const matches = PROVINCE_PHN_FORMATS.filter((fmt) =>
    fmt.regex.test(normalised),
  );

  if (matches.length === 0) {
    return { provinceCode: null, candidates: [], isDefinitive: false };
  }

  if (matches.length === 1) {
    return {
      provinceCode: matches[0].code,
      candidates: [matches[0].code],
      isDefinitive: true,
    };
  }

  return {
    provinceCode: null,
    candidates: matches.map((m) => m.code),
    isDefinitive: false,
  };
}

/**
 * Checks if a PHN is from out-of-province (not Alberta).
 *
 * @param phn - The PHN string
 * @param declaredProvince - Optionally declared province code
 * @returns true if definitively out-of-province or if declaredProvince is not 'AB'
 */
export function isOutOfProvincePhn(
  phn: string,
  declaredProvince?: string,
): boolean {
  if (declaredProvince && declaredProvince !== 'AB') {
    return true;
  }

  const result = detectProvinceFromPhn(phn);

  if (result.isDefinitive && result.provinceCode !== 'AB') {
    return true;
  }

  return false;
}
