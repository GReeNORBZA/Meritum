'use client';

import * as React from 'react';
import Link from 'next/link';
import { useArticleSearch } from '@/hooks/api/use-support';
import { useDebounce } from '@/hooks/use-debounce';
import { ROUTES } from '@/config/routes';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Search, FileText, X } from 'lucide-react';
import { cn } from '@/lib/utils';

interface HelpSearchProps {
  className?: string;
  placeholder?: string;
}

function HelpSearch({ className, placeholder = 'Search help articles...' }: HelpSearchProps) {
  const [query, setQuery] = React.useState('');
  const [isOpen, setIsOpen] = React.useState(false);
  const debouncedQuery = useDebounce(query, 300);
  const containerRef = React.useRef<HTMLDivElement>(null);

  const { data, isLoading } = useArticleSearch(debouncedQuery);
  const results = data?.data ?? [];

  // Close dropdown on outside click
  React.useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Open dropdown when there is a query
  React.useEffect(() => {
    if (debouncedQuery.length >= 2) {
      setIsOpen(true);
    } else {
      setIsOpen(false);
    }
  }, [debouncedQuery]);

  const clearSearch = () => {
    setQuery('');
    setIsOpen(false);
  };

  return (
    <div ref={containerRef} className={cn('relative', className)}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => {
            if (debouncedQuery.length >= 2) setIsOpen(true);
          }}
          placeholder={placeholder}
          className="pl-9 pr-9"
        />
        {query && (
          <button
            type="button"
            onClick={clearSearch}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {isOpen && (
        <div className="absolute top-full z-50 mt-1 w-full rounded-md border bg-popover shadow-lg">
          <div className="max-h-80 overflow-y-auto p-1">
            {isLoading ? (
              <div className="space-y-2 p-3">
                <Skeleton className="h-5 w-3/4" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-5 w-2/3 mt-3" />
                <Skeleton className="h-4 w-full" />
              </div>
            ) : results.length > 0 ? (
              results.map((article) => (
                <Link
                  key={article.slug}
                  href={ROUTES.SUPPORT_ARTICLE(article.slug)}
                  onClick={() => setIsOpen(false)}
                  className="flex items-start gap-3 rounded-sm p-3 hover:bg-accent transition-colors"
                >
                  <FileText className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0">
                    <p className="text-sm font-medium leading-tight truncate">
                      {article.title}
                    </p>
                    <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
                      {article.summary}
                    </p>
                  </div>
                </Link>
              ))
            ) : (
              <div className="p-4 text-center text-sm text-muted-foreground">
                No articles found for &quot;{debouncedQuery}&quot;
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export { HelpSearch };
