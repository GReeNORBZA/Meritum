export function maskPhn(phn: string): string {
  if (!phn || phn.length < 4) return phn;
  return phn.slice(0, 3) + '*'.repeat(phn.length - 3);
}

export function formatPhn(phn: string): string {
  if (!phn) return '';
  const digits = phn.replace(/\D/g, '');
  if (digits.length === 9) {
    return `${digits.slice(0, 3)}-${digits.slice(3, 6)}-${digits.slice(6)}`;
  }
  return digits;
}
