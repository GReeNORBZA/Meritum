'use client';

import { useFavouriteCodes, useToggleFavourite } from '@/hooks/api/use-reference';
import { cn } from '@/lib/utils';
import { Pin, PinOff, Loader2 } from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from '@/components/ui/tooltip';

export interface FavouriteCode {
  code: string;
  description: string;
  fee: number;
  pinned: boolean;
}

interface FavouriteCodesPaletteProps {
  onSelect: (code: string) => void;
  className?: string;
}

export function FavouriteCodesPalette({
  onSelect,
  className,
}: FavouriteCodesPaletteProps) {
  const { data, isLoading, isError } = useFavouriteCodes();
  const toggleFavourite = useToggleFavourite();

  const favourites = data?.data ?? [];

  if (isLoading) {
    return (
      <div className={cn('flex items-center justify-center py-4', className)}>
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <span className="ml-2 text-sm text-muted-foreground">
          Loading favourites...
        </span>
      </div>
    );
  }

  if (isError) {
    return (
      <div className={cn('text-sm text-destructive py-2', className)}>
        Failed to load favourite codes.
      </div>
    );
  }

  if (favourites.length === 0) {
    return (
      <div
        className={cn(
          'text-sm text-muted-foreground py-4 text-center',
          className
        )}
      >
        No favourite codes yet. Star codes from search results to see them here.
      </div>
    );
  }

  // Pinned codes first, then alphabetically
  const sorted = [...favourites].sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return a.code.localeCompare(b.code);
  });

  return (
    <TooltipProvider delayDuration={200}>
      <div className={cn('space-y-2', className)}>
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium text-muted-foreground">
            Favourite Codes
          </h4>
          <span className="text-xs text-muted-foreground">
            {favourites.length} code{favourites.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="grid grid-cols-3 gap-1.5 sm:grid-cols-4 md:grid-cols-5">
          {sorted.map((fav) => (
            <div
              key={fav.code}
              className="group relative flex items-center"
            >
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    onClick={() => onSelect(fav.code)}
                    className={cn(
                      'flex w-full flex-col items-center rounded-md border px-2 py-1.5 text-sm transition-colors',
                      'hover:bg-accent hover:text-accent-foreground',
                      'focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1',
                      fav.pinned && 'border-primary/30 bg-primary/5'
                    )}
                  >
                    <span className="font-mono font-semibold text-xs">
                      {fav.code}
                    </span>
                    <span className="text-[10px] text-muted-foreground truncate w-full text-center leading-tight mt-0.5">
                      {fav.description}
                    </span>
                  </button>
                </TooltipTrigger>
                <TooltipContent side="bottom">
                  <p className="font-mono font-medium">{fav.code}</p>
                  <p className="text-xs">{fav.description}</p>
                </TooltipContent>
              </Tooltip>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  toggleFavourite.mutate(fav.code);
                }}
                className={cn(
                  'absolute -right-1 -top-1 rounded-full p-0.5 transition-opacity',
                  'bg-background border shadow-sm',
                  'opacity-0 group-hover:opacity-100 focus:opacity-100',
                  'hover:text-primary focus:outline-none focus:ring-1 focus:ring-ring'
                )}
                aria-label={fav.pinned ? `Unpin ${fav.code}` : `Pin ${fav.code}`}
              >
                {fav.pinned ? (
                  <PinOff className="h-3 w-3" />
                ) : (
                  <Pin className="h-3 w-3" />
                )}
              </button>
            </div>
          ))}
        </div>
      </div>
    </TooltipProvider>
  );
}
