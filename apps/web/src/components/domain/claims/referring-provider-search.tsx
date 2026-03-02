'use client';

import { useState, useEffect, useCallback } from 'react';
import { useDebounce } from '@/hooks/use-debounce';
import { useReferringProviderSearch } from '@/hooks/api/use-reference';
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
  CommandSeparator,
} from '@/components/ui/command';
import { Button } from '@/components/ui/button';
import { ChevronsUpDown, Check, Loader2, Clock, X } from 'lucide-react';

export interface ReferringProvider {
  billing_number: string;
  first_name: string;
  last_name: string;
  specialty?: string;
  city?: string;
}

interface ReferringProviderSearchProps {
  value: string | null;
  onValueChange: (billingNumber: string | null) => void;
  disabled?: boolean;
  className?: string;
}

const MRU_STORAGE_KEY = 'meritum:mru-referring-providers';
const MRU_MAX = 5;

function getMru(): ReferringProvider[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(MRU_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function addToMru(provider: ReferringProvider) {
  const current = getMru().filter(
    (p) => p.billing_number !== provider.billing_number
  );
  const updated = [provider, ...current].slice(0, MRU_MAX);
  try {
    localStorage.setItem(MRU_STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // localStorage may be unavailable
  }
}

export function ReferringProviderSearch({
  value,
  onValueChange,
  disabled,
  className,
}: ReferringProviderSearchProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [mruProviders, setMruProviders] = useState<ReferringProvider[]>([]);
  const [selectedLabel, setSelectedLabel] = useState('');
  const debouncedQuery = useDebounce(query, 300);

  const { data, isLoading } = useReferringProviderSearch(debouncedQuery);
  const results = data?.data ?? [];

  useEffect(() => {
    setMruProviders(getMru());
  }, [open]);

  // Resolve the display name for the current value from results or MRU
  useEffect(() => {
    if (!value) {
      setSelectedLabel('');
      return;
    }
    const fromResults = results.find((p) => p.billing_number === value);
    if (fromResults) {
      setSelectedLabel(
        `Dr. ${fromResults.last_name}, ${fromResults.first_name}`
      );
      return;
    }
    const fromMru = mruProviders.find((p) => p.billing_number === value);
    if (fromMru) {
      setSelectedLabel(`Dr. ${fromMru.last_name}, ${fromMru.first_name}`);
    }
  }, [value, results, mruProviders]);

  const handleSelect = useCallback(
    (provider: ReferringProvider) => {
      const isCurrentlySelected = value === provider.billing_number;
      if (isCurrentlySelected) {
        onValueChange(null);
        setSelectedLabel('');
      } else {
        onValueChange(provider.billing_number);
        setSelectedLabel(
          `Dr. ${provider.last_name}, ${provider.first_name}`
        );
        addToMru(provider);
      }
      setOpen(false);
    },
    [value, onValueChange]
  );

  const formatProvider = (provider: ReferringProvider) => (
    <div className="flex flex-col">
      <span className="font-medium">
        Dr. {provider.last_name}, {provider.first_name}
      </span>
      <span className="text-xs text-muted-foreground">
        {provider.billing_number}
        {provider.specialty && ` \u00b7 ${provider.specialty}`}
        {provider.city && ` \u00b7 ${provider.city}`}
      </span>
    </div>
  );

  const showMru =
    mruProviders.length > 0 && debouncedQuery.length < 2;

  return (
    <div className={className}>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className={cn(
              'w-full justify-between',
              !value && 'text-muted-foreground'
            )}
            disabled={disabled}
          >
            <span className="truncate">
              {value ? selectedLabel || value : 'Select referring provider...'}
            </span>
            <div className="flex items-center gap-1 ml-2 shrink-0">
              {value && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onValueChange(null);
                    setSelectedLabel('');
                  }}
                  className="rounded-full hover:text-destructive focus:outline-none"
                  aria-label="Clear selection"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
              <ChevronsUpDown className="h-4 w-4 opacity-50" />
            </div>
          </Button>
        </PopoverTrigger>
        <PopoverContent
          className="w-[var(--radix-popover-trigger-width)] p-0"
          align="start"
        >
          <Command shouldFilter={false}>
            <CommandInput
              placeholder="Search by name or billing number..."
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
                  'No referring providers found'
                )}
              </CommandEmpty>

              {showMru && (
                <CommandGroup heading="Recently Used">
                  {mruProviders.map((provider) => (
                    <CommandItem
                      key={`mru-${provider.billing_number}`}
                      value={provider.billing_number}
                      onSelect={() => handleSelect(provider)}
                    >
                      <Clock className="mr-2 h-4 w-4 shrink-0 text-muted-foreground" />
                      {formatProvider(provider)}
                      <Check
                        className={cn(
                          'ml-auto h-4 w-4',
                          value === provider.billing_number
                            ? 'opacity-100'
                            : 'opacity-0'
                        )}
                      />
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}

              {showMru && results.length > 0 && <CommandSeparator />}

              {results.length > 0 && (
                <CommandGroup heading={showMru ? 'Search Results' : undefined}>
                  {results.map((provider) => (
                    <CommandItem
                      key={provider.billing_number}
                      value={provider.billing_number}
                      onSelect={() => handleSelect(provider)}
                    >
                      <Check
                        className={cn(
                          'mr-2 h-4 w-4 shrink-0',
                          value === provider.billing_number
                            ? 'opacity-100'
                            : 'opacity-0'
                        )}
                      />
                      {formatProvider(provider)}
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    </div>
  );
}
