'use client';

import * as React from 'react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

type MoneyInputProps = Omit<
  React.InputHTMLAttributes<HTMLInputElement>,
  'type'
>;

function formatCurrency(value: string): string {
  const num = parseFloat(value);
  if (isNaN(num)) return value;
  return num.toFixed(2);
}

function stripFormatting(value: string): string {
  return value.replace(/[^0-9.]/g, '');
}

const MoneyInput = React.forwardRef<HTMLInputElement, MoneyInputProps>(
  ({ className, value, onChange, onBlur, onFocus, ...props }, ref) => {
    const [displayValue, setDisplayValue] = React.useState<string>(
      value != null ? String(value) : ''
    );
    const [isFocused, setIsFocused] = React.useState(false);

    React.useEffect(() => {
      if (!isFocused && value != null) {
        const raw = stripFormatting(String(value));
        setDisplayValue(raw ? formatCurrency(raw) : '');
      }
    }, [value, isFocused]);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const raw = stripFormatting(e.target.value);
      const parts = raw.split('.');
      if (parts.length > 2) return;
      if (parts[1] && parts[1].length > 2) return;
      setDisplayValue(raw);
      if (onChange) {
        const syntheticEvent = {
          ...e,
          target: { ...e.target, value: raw },
        } as React.ChangeEvent<HTMLInputElement>;
        onChange(syntheticEvent);
      }
    };

    const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(true);
      const raw = stripFormatting(e.target.value);
      setDisplayValue(raw);
      onFocus?.(e);
    };

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(false);
      const raw = stripFormatting(e.target.value);
      if (raw) {
        setDisplayValue(formatCurrency(raw));
      }
      onBlur?.(e);
    };

    return (
      <div className="relative">
        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-muted-foreground">
          $
        </span>
        <Input
          ref={ref}
          type="text"
          inputMode="decimal"
          className={cn('pl-7', className)}
          value={displayValue}
          onChange={handleChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          {...props}
        />
      </div>
    );
  }
);
MoneyInput.displayName = 'MoneyInput';

export { MoneyInput };
