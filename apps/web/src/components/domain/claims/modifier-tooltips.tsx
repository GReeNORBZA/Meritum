'use client';

import { cn } from '@/lib/utils';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from '@/components/ui/tooltip';
import { Info } from 'lucide-react';

export interface Modifier {
  code: string;
  label: string;
  description: string;
  eligible: boolean;
}

interface ModifierTooltipsProps {
  modifiers: Modifier[];
  selected: string[];
  onToggle: (code: string) => void;
  disabled?: boolean;
  className?: string;
}

export function ModifierTooltips({
  modifiers,
  selected,
  onToggle,
  disabled,
  className,
}: ModifierTooltipsProps) {
  if (modifiers.length === 0) {
    return (
      <div className={cn('text-sm text-muted-foreground py-1', className)}>
        No modifiers available for this code.
      </div>
    );
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className={cn('space-y-2', className)}>
        <label className="text-sm font-medium leading-none">Modifiers</label>
        <div className="flex flex-wrap gap-2">
          {modifiers.map((modifier) => {
            const isSelected = selected.includes(modifier.code);
            const isIneligible = !modifier.eligible;

            return (
              <div key={modifier.code} className="flex items-center gap-1.5">
                <button
                  type="button"
                  role="checkbox"
                  aria-checked={isSelected}
                  aria-label={`${modifier.label} modifier`}
                  disabled={disabled || isIneligible}
                  onClick={() => onToggle(modifier.code)}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors',
                    'focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1',
                    isSelected
                      ? 'border-primary bg-primary text-primary-foreground'
                      : 'border-input bg-background hover:bg-accent hover:text-accent-foreground',
                    (disabled || isIneligible) &&
                      'cursor-not-allowed opacity-50'
                  )}
                >
                  <span className="font-mono text-xs">{modifier.code}</span>
                  <span>{modifier.label}</span>
                </button>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      type="button"
                      className="text-muted-foreground hover:text-foreground focus:outline-none"
                      aria-label={`Info about ${modifier.label}`}
                    >
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent
                    side="top"
                    className="max-w-[280px]"
                  >
                    <p className="font-medium">
                      {modifier.code} &mdash; {modifier.label}
                    </p>
                    <p className="mt-1 text-xs">{modifier.description}</p>
                    {isIneligible && (
                      <p className="mt-1 text-xs font-medium text-warning-foreground">
                        This modifier is not eligible for the selected HSC code.
                      </p>
                    )}
                  </TooltipContent>
                </Tooltip>
              </div>
            );
          })}
        </div>
        {selected.length > 0 && (
          <p className="text-xs text-muted-foreground">
            {selected.length} modifier{selected.length !== 1 ? 's' : ''}{' '}
            selected: {selected.join(', ')}
          </p>
        )}
      </div>
    </TooltipProvider>
  );
}
