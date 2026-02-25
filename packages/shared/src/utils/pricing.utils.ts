import {
  BASE_MONTHLY_RATE,
  DISCOUNT_ANNUAL_PERCENT,
  DISCOUNT_CLINIC_PERCENT,
  DISCOUNT_CEILING_PERCENT,
  MINIMUM_RATE_FLOOR,
  EARLY_BIRD_MONTHLY_RATE,
} from '../constants/platform.constants.js';

export interface EffectiveRateResult {
  monthlyRate: number;
  annualRate: number | null;
  appliedDiscounts: string[];
  totalDiscountPercent: number;
}

/**
 * Calculate the effective subscription rate based on billing frequency and tier.
 *
 * Rules (from Pricing Gap Closure Spec B2-1):
 * 1. Base rate: $279/month
 * 2. Annual billing: 5% off base → $265.05/month, $3,180.60/year
 * 3. Clinic tier: 10% off base → $251.10/month
 * 4. Clinic + annual: 15% off (ceiling) → $237.15/month, $2,845.80/year
 * 5. Early bird: flat $199/month — NO discounts stack on early bird
 * 6. No configuration produces a rate below 85% of $279 ($237.15)
 */
export function calculateEffectiveRate(
  baseMonthly: number,
  isAnnual: boolean,
  isClinic: boolean,
): EffectiveRateResult {
  // Handle edge cases
  if (!Number.isFinite(baseMonthly) || baseMonthly < 0) {
    return {
      monthlyRate: 0,
      annualRate: isAnnual ? 0 : null,
      appliedDiscounts: [],
      totalDiscountPercent: 0,
    };
  }

  let totalDiscountPercent = 0;
  const appliedDiscounts: string[] = [];

  if (isAnnual) {
    totalDiscountPercent += DISCOUNT_ANNUAL_PERCENT;
    appliedDiscounts.push(`Annual billing (${DISCOUNT_ANNUAL_PERCENT}%)`);
  }

  if (isClinic) {
    totalDiscountPercent += DISCOUNT_CLINIC_PERCENT;
    appliedDiscounts.push(`Clinic tier (${DISCOUNT_CLINIC_PERCENT}%)`);
  }

  // Cap at ceiling
  if (totalDiscountPercent > DISCOUNT_CEILING_PERCENT) {
    totalDiscountPercent = DISCOUNT_CEILING_PERCENT;
  }

  let monthlyRate = Math.round(baseMonthly * (1 - totalDiscountPercent / 100) * 100) / 100;

  // Enforce floor
  const floor = Math.round(baseMonthly * (1 - DISCOUNT_CEILING_PERCENT / 100) * 100) / 100;
  if (monthlyRate < floor) {
    monthlyRate = floor;
  }

  const annualRate = isAnnual ? Math.round(monthlyRate * 12 * 100) / 100 : null;

  return {
    monthlyRate,
    annualRate,
    appliedDiscounts,
    totalDiscountPercent,
  };
}

/**
 * Check if a rate qualifies as an early bird rate.
 * Early bird is a flat rate — no discount stacking allowed.
 */
export function isEarlyBirdRate(plan: string): boolean {
  return plan.includes('EARLY_BIRD');
}

/**
 * Get the early bird effective rate. No discounts apply.
 * Annual early bird = $199 * 12 = $2,388 (no additional discount).
 */
export function getEarlyBirdRate(isAnnual: boolean): EffectiveRateResult {
  return {
    monthlyRate: EARLY_BIRD_MONTHLY_RATE,
    annualRate: isAnnual ? EARLY_BIRD_MONTHLY_RATE * 12 : null,
    appliedDiscounts: [],
    totalDiscountPercent: 0,
  };
}
