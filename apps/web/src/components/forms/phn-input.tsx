'use client';

import * as React from 'react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

type PhnInputProps = Omit<
  React.InputHTMLAttributes<HTMLInputElement>,
  'type' | 'maxLength' | 'inputMode'
>;

function formatPhn(digits: string): string {
  if (digits.length <= 3) return digits;
  if (digits.length <= 6) return `${digits.slice(0, 3)}-${digits.slice(3)}`;
  return `${digits.slice(0, 3)}-${digits.slice(3, 6)}-${digits.slice(6)}`;
}

const PhnInput = React.forwardRef<HTMLInputElement, PhnInputProps>(
  ({ className, value, onChange, ...props }, ref) => {
    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const raw = e.target.value.replace(/\D/g, '').slice(0, 9);
      const formatted = formatPhn(raw);

      if (onChange) {
        const syntheticEvent = {
          ...e,
          target: { ...e.target, value: formatted },
        } as React.ChangeEvent<HTMLInputElement>;
        onChange(syntheticEvent);
      }
    };

    const displayValue = React.useMemo(() => {
      if (value == null || value === '') return '';
      const digits = String(value).replace(/\D/g, '').slice(0, 9);
      return formatPhn(digits);
    }, [value]);

    return (
      <Input
        ref={ref}
        type="text"
        inputMode="numeric"
        maxLength={11}
        placeholder="123-456-789"
        className={cn('font-mono', className)}
        value={displayValue}
        onChange={handleChange}
        {...props}
      />
    );
  }
);
PhnInput.displayName = 'PhnInput';

export { PhnInput };
