export const pricingConfig = {
  earlyBird: {
    active: true,
    spotsTotal: 100,
    spotsRemaining: 100,
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

export type PricingConfig = typeof pricingConfig;

export function getCurrentRate(config: PricingConfig = pricingConfig) {
  return config.earlyBird.active
    ? { monthly: config.earlyBird.monthlyRate, annual: config.earlyBird.annualRate, label: 'Early bird' }
    : { monthly: config.standard.monthlyRate, annual: config.standard.annualRate, label: 'Standard' };
}

export function formatCAD(amount: number): string {
  return `$${amount.toLocaleString('en-CA')}`;
}
