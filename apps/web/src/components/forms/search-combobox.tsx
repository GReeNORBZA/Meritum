'use client';

import * as React from 'react';
import { Check, ChevronsUpDown, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { useDebounce } from '@/hooks/use-debounce';

export interface ComboboxOption {
  value: string;
  label: string;
  description?: string;
}

interface SearchComboboxProps {
  value: string;
  onValueChange: (value: string) => void;
  searchFn: (query: string) => Promise<ComboboxOption[]>;
  placeholder?: string;
  emptyMessage?: string;
  disabled?: boolean;
  className?: string;
}

function SearchCombobox({
  value,
  onValueChange,
  searchFn,
  placeholder = 'Select...',
  emptyMessage = 'No results found.',
  disabled,
  className,
}: SearchComboboxProps) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState('');
  const [options, setOptions] = React.useState<ComboboxOption[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);

  const debouncedQuery = useDebounce(query, 300);

  const selectedOption = options.find((opt) => opt.value === value);
  const [selectedLabel, setSelectedLabel] = React.useState('');

  React.useEffect(() => {
    if (selectedOption) {
      setSelectedLabel(selectedOption.label);
    }
  }, [selectedOption]);

  React.useEffect(() => {
    let cancelled = false;

    async function fetchOptions() {
      setIsLoading(true);
      try {
        const results = await searchFn(debouncedQuery);
        if (!cancelled) {
          setOptions(results);
        }
      } catch {
        if (!cancelled) {
          setOptions([]);
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    if (open) {
      fetchOptions();
    }

    return () => {
      cancelled = true;
    };
  }, [debouncedQuery, open, searchFn]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className={cn(
            'w-full justify-between',
            !value && 'text-muted-foreground',
            className
          )}
          disabled={disabled}
        >
          {value ? selectedLabel || value : placeholder}
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="w-[var(--radix-popover-trigger-width)] p-0"
        align="start"
      >
        <Command shouldFilter={false}>
          <CommandInput
            placeholder="Search..."
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
              ) : (
                emptyMessage
              )}
            </CommandEmpty>
            <CommandGroup>
              {options.map((option) => (
                <CommandItem
                  key={option.value}
                  value={option.value}
                  onSelect={() => {
                    onValueChange(
                      option.value === value ? '' : option.value
                    );
                    setSelectedLabel(option.label);
                    setOpen(false);
                  }}
                >
                  <Check
                    className={cn(
                      'mr-2 h-4 w-4',
                      value === option.value ? 'opacity-100' : 'opacity-0'
                    )}
                  />
                  <div className="flex flex-col">
                    <span>{option.label}</span>
                    {option.description && (
                      <span className="text-xs text-muted-foreground">
                        {option.description}
                      </span>
                    )}
                  </div>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

export { SearchCombobox };
export type { SearchComboboxProps };
