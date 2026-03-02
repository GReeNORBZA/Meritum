'use client';

import { useState } from 'react';
import { useDebounce } from '@/hooks/use-debounce';
import { useDiagnosticSearch } from '@/hooks/api/use-reference';
import { cn } from '@/lib/utils';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import {
  Command,
  CommandInput,
  CommandList,
  CommandItem,
  CommandEmpty,
  CommandGroup,
} from '@/components/ui/command';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { X, Search, Check, Loader2 } from 'lucide-react';

export interface DiagnosticCode {
  code: string;
  description: string;
  type: 'ICD-9' | 'ICD-10';
  chapter?: string;
}

interface DiagnosticSearchProps {
  value: string[];
  onValueChange: (codes: string[]) => void;
  max?: number;
  disabled?: boolean;
  className?: string;
}

function highlightMatch(text: string, query: string) {
  if (!query || query.length < 2) return text;
  const regex = new RegExp(
    `(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`,
    'gi'
  );
  const parts = text.split(regex);

  return parts.map((part, i) =>
    regex.test(part) ? (
      <mark
        key={i}
        className="bg-yellow-200 dark:bg-yellow-800 rounded-sm px-0.5"
      >
        {part}
      </mark>
    ) : (
      part
    )
  );
}

export function DiagnosticSearch({
  value,
  onValueChange,
  max = 3,
  disabled,
  className,
}: DiagnosticSearchProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebounce(query, 300);

  const { data, isLoading } = useDiagnosticSearch(debouncedQuery);
  const results = data?.data ?? [];

  const handleSelect = (code: string) => {
    if (value.includes(code)) {
      onValueChange(value.filter((c) => c !== code));
    } else if (value.length < max) {
      onValueChange([...value, code]);
    }
  };

  const handleRemove = (code: string) => {
    onValueChange(value.filter((c) => c !== code));
  };

  return (
    <div className={cn('space-y-2', className)}>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className="w-full justify-start text-left font-normal"
            disabled={disabled}
          >
            <Search className="mr-2 h-4 w-4 text-muted-foreground" />
            {value.length > 0
              ? `${value.length} diagnosis code${value.length > 1 ? 's' : ''} selected`
              : 'Search diagnostic codes...'}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[460px] p-0" align="start">
          <Command shouldFilter={false}>
            <CommandInput
              placeholder="Type ICD code or description..."
              value={query}
              onValueChange={setQuery}
            />
            <CommandList>
              <CommandEmpty>
                {isLoading ? (
                  <div className="flex items-center justify-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Searching...</span>
                  </div>
                ) : debouncedQuery.length < 2 ? (
                  'Type at least 2 characters to search'
                ) : (
                  'No diagnostic codes found'
                )}
              </CommandEmpty>
              <CommandGroup>
                {results.map((dx) => {
                  const isSelected = value.includes(dx.code);
                  const isDisabled = !isSelected && value.length >= max;

                  return (
                    <CommandItem
                      key={dx.code}
                      value={dx.code}
                      onSelect={() => !isDisabled && handleSelect(dx.code)}
                      className={cn(isDisabled && 'opacity-50')}
                    >
                      <Check
                        className={cn(
                          'mr-2 h-4 w-4 shrink-0',
                          isSelected ? 'opacity-100' : 'opacity-0'
                        )}
                      />
                      <div className="flex items-center justify-between w-full min-w-0">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-mono font-medium shrink-0">
                            {highlightMatch(dx.code, debouncedQuery)}
                          </span>
                          <span className="text-sm text-muted-foreground truncate">
                            {highlightMatch(dx.description, debouncedQuery)}
                          </span>
                        </div>
                        <Badge
                          variant="outline"
                          className="shrink-0 ml-2 text-xs"
                        >
                          {dx.type}
                        </Badge>
                      </div>
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            </CommandList>
            {value.length >= max && (
              <div className="border-t px-3 py-2 text-xs text-muted-foreground">
                Maximum of {max} diagnostic codes reached. Remove one to add
                another.
              </div>
            )}
          </Command>
        </PopoverContent>
      </Popover>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {value.map((code) => (
            <Badge key={code} variant="secondary" className="gap-1">
              <span className="font-mono">{code}</span>
              <button
                type="button"
                onClick={() => handleRemove(code)}
                className="ml-1 rounded-full hover:text-destructive focus:outline-none focus:ring-1 focus:ring-ring"
                aria-label={`Remove ${code}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
