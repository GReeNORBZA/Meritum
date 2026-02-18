import { describe, it, expect } from 'vitest';
import { validateAlbertaPhn, maskPhn } from '@meritum/shared';

describe('validateAlbertaPhn', () => {
  it('accepts a valid Alberta PHN passing Luhn check', () => {
    // 1234 5674 0 — Luhn-valid 9-digit number
    // Compute: 0+(7*2=14-9=5)+4+(5*2=10-9=1)+6+(3*2=6)+2+(1*2=2)+0 = 0+5+4+1+6+6+2+2+0 ≠ ...
    // Use known valid: 123456782
    // Verification: digits right-to-left: 2,8,7,6,5,4,3,2,1
    // Positions from right (0-indexed): 0,1,2,3,4,5,6,7,8
    // Odd positions (doubled): pos1=8*2=16→1+6=7, pos3=6*2=12→1+2=3, pos5=4*2=8, pos7=2*2=4
    // Even positions (as-is): pos0=2, pos2=7, pos4=5, pos6=3, pos8=1
    // Sum = 2+7+7+3+5+8+3+4+1 = 40 → 40%10=0 ✓
    const result = validateAlbertaPhn('123456782');
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('rejects a PHN with invalid Luhn check digit', () => {
    const result = validateAlbertaPhn('123456789');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Luhn');
  });

  it('rejects a PHN shorter than 9 digits', () => {
    const result = validateAlbertaPhn('12345678');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('9 digits');
  });

  it('rejects a PHN longer than 9 digits', () => {
    const result = validateAlbertaPhn('1234567890');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('9 digits');
  });

  it('rejects non-numeric characters', () => {
    const result = validateAlbertaPhn('12345678A');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('9 digits');
  });

  it('rejects empty string', () => {
    const result = validateAlbertaPhn('');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('9 digits');
  });

  it('rejects PHN with spaces', () => {
    const result = validateAlbertaPhn('123 456 78');
    expect(result.valid).toBe(false);
  });

  it('rejects PHN with dashes', () => {
    const result = validateAlbertaPhn('123-456-78');
    expect(result.valid).toBe(false);
  });

  it('accepts another known Luhn-valid PHN (all zeros check)', () => {
    // 000000000 → sum of all zeros = 0, 0%10=0 → valid
    const result = validateAlbertaPhn('000000000');
    expect(result.valid).toBe(true);
  });

  it('accepts Luhn-valid PHN 000000018', () => {
    // digits right-to-left: 8,1,0,0,0,0,0,0,0
    // pos0=8, pos1=1*2=2, pos2-8=0
    // sum = 8+2 = 10, 10%10=0 ✓
    const result = validateAlbertaPhn('000000018');
    expect(result.valid).toBe(true);
  });
});

describe('maskPhn', () => {
  it('masks a 9-digit PHN showing first 3 digits', () => {
    expect(maskPhn('123456789')).toBe('123******');
  });

  it('masks another PHN correctly', () => {
    expect(maskPhn('987654321')).toBe('987******');
  });

  it('handles short strings gracefully', () => {
    expect(maskPhn('12')).toBe('***');
  });

  it('handles empty string', () => {
    expect(maskPhn('')).toBe('***');
  });

  it('handles exactly 3-character string', () => {
    expect(maskPhn('123')).toBe('123');
  });

  it('masks a 10-digit string showing first 3', () => {
    expect(maskPhn('1234567890')).toBe('123*******');
  });
});
