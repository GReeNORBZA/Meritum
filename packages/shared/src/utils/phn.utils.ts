// ============================================================================
// Domain 6: Patient Registry — PHN Utilities
// ============================================================================

/**
 * Validates an Alberta Personal Health Number (PHN).
 *
 * Alberta PHNs are 9-digit numeric strings validated using the Luhn algorithm
 * (modulus 10, double-add-double on odd positions from right).
 *
 * @param phn - The PHN string to validate
 * @returns Validation result with optional error message
 */
export function validateAlbertaPhn(phn: string): {
  valid: boolean;
  error?: string;
} {
  if (typeof phn !== 'string') {
    return { valid: false, error: 'PHN must be a string' };
  }

  if (!/^\d{9}$/.test(phn)) {
    return { valid: false, error: 'PHN must be exactly 9 digits' };
  }

  // Luhn algorithm (modulus 10)
  // Process digits from right to left, doubling every second digit
  let sum = 0;
  for (let i = phn.length - 1; i >= 0; i--) {
    let digit = parseInt(phn[i], 10);
    const positionFromRight = phn.length - 1 - i;

    // Double digits at odd positions from the right (1, 3, 5, 7)
    if (positionFromRight % 2 === 1) {
      digit *= 2;
      // If doubling results in a number > 9, subtract 9 (equivalent to summing digits)
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
  }

  if (sum % 10 !== 0) {
    return { valid: false, error: 'PHN failed Luhn check digit validation' };
  }

  return { valid: true };
}

/**
 * Masks a PHN for display in audit logs and admin views.
 *
 * Shows the first 3 digits and replaces the remaining 6 with asterisks.
 * Example: "123456789" → "123******"
 *
 * @param phn - The PHN string to mask
 * @returns Masked PHN string
 */
export function maskPhn(phn: string): string {
  if (typeof phn !== 'string' || phn.length < 3) {
    return '***';
  }

  return phn.slice(0, 3) + '*'.repeat(phn.length - 3);
}
