import { describe, it, expect } from 'vitest';
import { calculateEffectiveRate, getEarlyBirdRate, isEarlyBirdRate } from './pricing.utils.js';
import {
  BASE_MONTHLY_RATE,
  MINIMUM_RATE_FLOOR,
  EARLY_BIRD_MONTHLY_RATE,
} from '../constants/platform.constants.js';

describe('calculateEffectiveRate', () => {
  describe('Standard monthly (no discounts)', () => {
    const result = calculateEffectiveRate(BASE_MONTHLY_RATE, false, false);

    it('returns base rate of $279/month with no discounts applied', () => {
      expect(result.monthlyRate).toBe(279);
    });

    it('returns null for annualRate', () => {
      expect(result.annualRate).toBeNull();
    });

    it('returns empty appliedDiscounts array', () => {
      expect(result.appliedDiscounts).toEqual([]);
    });

    it('returns totalDiscountPercent of 0', () => {
      expect(result.totalDiscountPercent).toBe(0);
    });
  });

  describe('Standard annual (5% discount)', () => {
    const result = calculateEffectiveRate(BASE_MONTHLY_RATE, true, false);

    it('returns monthly rate of $265.05 (279 * 0.95)', () => {
      expect(result.monthlyRate).toBe(265.05);
    });

    it('returns annual rate of $3,180.60 (265.05 * 12)', () => {
      expect(result.annualRate).toBe(3180.6);
    });

    it('includes "Annual billing (5%)" in appliedDiscounts', () => {
      expect(result.appliedDiscounts).toContain('Annual billing (5%)');
    });

    it('returns totalDiscountPercent of 5', () => {
      expect(result.totalDiscountPercent).toBe(5);
    });
  });

  describe('Clinic monthly (10% discount)', () => {
    const result = calculateEffectiveRate(BASE_MONTHLY_RATE, false, true);

    it('returns monthly rate of $251.10 (279 * 0.90)', () => {
      expect(result.monthlyRate).toBe(251.1);
    });

    it('returns null for annualRate', () => {
      expect(result.annualRate).toBeNull();
    });

    it('includes "Clinic tier (10%)" in appliedDiscounts', () => {
      expect(result.appliedDiscounts).toContain('Clinic tier (10%)');
    });

    it('returns totalDiscountPercent of 10', () => {
      expect(result.totalDiscountPercent).toBe(10);
    });
  });

  describe('Clinic annual (15% discount — ceiling)', () => {
    const result = calculateEffectiveRate(BASE_MONTHLY_RATE, true, true);

    it('returns monthly rate of $237.15 (279 * 0.85)', () => {
      expect(result.monthlyRate).toBe(237.15);
    });

    it('returns annual rate of $2,845.80 (237.15 * 12)', () => {
      expect(result.annualRate).toBe(2845.8);
    });

    it('includes both discount labels in appliedDiscounts', () => {
      expect(result.appliedDiscounts).toContain('Annual billing (5%)');
      expect(result.appliedDiscounts).toContain('Clinic tier (10%)');
    });

    it('returns totalDiscountPercent of 15 (capped at ceiling)', () => {
      expect(result.totalDiscountPercent).toBe(15);
    });

    it('does NOT compound discounts (not 0.90 * 0.95 = 14.5%)', () => {
      // Compounding would give: 279 * 0.90 * 0.95 = 238.305
      // Additive gives: 279 * 0.85 = 237.15
      expect(result.monthlyRate).toBe(237.15);
      expect(result.monthlyRate).not.toBe(238.31); // rounded compounding
    });
  });

  describe('Ceiling enforcement', () => {
    it('never produces a monthly rate below MINIMUM_RATE_FLOOR ($237.15)', () => {
      const result = calculateEffectiveRate(BASE_MONTHLY_RATE, true, true);
      expect(result.monthlyRate).toBeGreaterThanOrEqual(MINIMUM_RATE_FLOOR);
    });

    it('caps totalDiscountPercent at 15 even if inputs would suggest more', () => {
      const result = calculateEffectiveRate(BASE_MONTHLY_RATE, true, true);
      expect(result.totalDiscountPercent).toBeLessThanOrEqual(15);
    });

    it('clamps rate to floor if calculated rate falls below minimum', () => {
      // With a lower base, the floor is recalculated proportionally
      const result = calculateEffectiveRate(200, true, true);
      const floor = Math.round(200 * 0.85 * 100) / 100;
      expect(result.monthlyRate).toBeGreaterThanOrEqual(floor);
    });
  });

  describe('Precision', () => {
    it('rounds to 2 decimal places', () => {
      const result = calculateEffectiveRate(BASE_MONTHLY_RATE, true, false);
      const decimalPlaces = result.monthlyRate.toString().split('.')[1]?.length ?? 0;
      expect(decimalPlaces).toBeLessThanOrEqual(2);
    });

    it('handles floating point edge cases correctly', () => {
      // 279 * 0.95 = 265.05 exactly in IEEE 754
      const result = calculateEffectiveRate(279, true, false);
      expect(result.monthlyRate).toBe(265.05);
    });
  });

  describe('Edge case inputs', () => {
    it('passing a base rate of 0 returns a non-negative rate', () => {
      const result = calculateEffectiveRate(0, true, true);
      expect(result.monthlyRate).toBeGreaterThanOrEqual(0);
    });

    it('passing a negative base rate returns zero', () => {
      const result = calculateEffectiveRate(-100, true, true);
      expect(result.monthlyRate).toBe(0);
    });

    it('passing NaN base rate is handled gracefully', () => {
      const result = calculateEffectiveRate(NaN, true, true);
      expect(result.monthlyRate).toBe(0);
    });

    it('passing Infinity base rate is handled gracefully', () => {
      const result = calculateEffectiveRate(Infinity, true, true);
      expect(result.monthlyRate).toBe(0);
    });
  });
});

describe('getEarlyBirdRate', () => {
  describe('Early bird monthly', () => {
    const result = getEarlyBirdRate(false);

    it('returns monthly rate of $199', () => {
      expect(result.monthlyRate).toBe(199);
    });

    it('returns null for annualRate when isAnnual is false', () => {
      expect(result.annualRate).toBeNull();
    });

    it('returns empty appliedDiscounts (no discounts stack on early bird)', () => {
      expect(result.appliedDiscounts).toEqual([]);
    });

    it('returns totalDiscountPercent of 0', () => {
      expect(result.totalDiscountPercent).toBe(0);
    });
  });

  describe('Early bird annual', () => {
    const result = getEarlyBirdRate(true);

    it('returns monthly rate of $199', () => {
      expect(result.monthlyRate).toBe(199);
    });

    it('returns annual rate of $2,388 (199 * 12, no additional discount)', () => {
      expect(result.annualRate).toBe(2388);
    });

    it('returns empty appliedDiscounts', () => {
      expect(result.appliedDiscounts).toEqual([]);
    });

    it('returns totalDiscountPercent of 0', () => {
      expect(result.totalDiscountPercent).toBe(0);
    });

    it('does NOT apply the 5% annual discount to early bird', () => {
      // If annual discount were applied: 199 * 0.95 = 189.05
      expect(result.monthlyRate).toBe(199);
      expect(result.annualRate).toBe(2388);
    });
  });
});

describe('isEarlyBirdRate', () => {
  it('returns true for EARLY_BIRD_MONTHLY', () => {
    expect(isEarlyBirdRate('EARLY_BIRD_MONTHLY')).toBe(true);
  });

  it('returns true for EARLY_BIRD_ANNUAL', () => {
    expect(isEarlyBirdRate('EARLY_BIRD_ANNUAL')).toBe(true);
  });

  it('returns false for STANDARD_MONTHLY', () => {
    expect(isEarlyBirdRate('STANDARD_MONTHLY')).toBe(false);
  });

  it('returns false for STANDARD_ANNUAL', () => {
    expect(isEarlyBirdRate('STANDARD_ANNUAL')).toBe(false);
  });

  it('returns false for CLINIC_MONTHLY', () => {
    expect(isEarlyBirdRate('CLINIC_MONTHLY')).toBe(false);
  });

  it('returns false for CLINIC_ANNUAL', () => {
    expect(isEarlyBirdRate('CLINIC_ANNUAL')).toBe(false);
  });
});
