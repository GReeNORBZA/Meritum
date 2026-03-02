'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  Star,
  ChevronUp,
  ChevronDown,
  Loader2,
  Plus,
  Trash2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ApiResponse } from '@/lib/api/client';

interface FavouriteCode {
  id: string;
  health_service_code: string;
  description: string;
  sort_order: number;
}

export default function MobileFavouritesPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [newCode, setNewCode] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: queryKeys.reference.favourites(),
    queryFn: () =>
      api.get<ApiResponse<FavouriteCode[]>>('/api/v1/favourites'),
  });

  const favourites = data?.data ?? [];

  const reorderMutation = useMutation({
    mutationFn: (reordered: { id: string; sort_order: number }[]) =>
      api.put('/api/v1/favourites/reorder', { items: reordered }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.favourites() });
    },
  });

  const addMutation = useMutation({
    mutationFn: (code: string) =>
      api.post<ApiResponse<FavouriteCode>>('/api/v1/favourites', {
        health_service_code: code,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.favourites() });
      setNewCode('');
      setShowAddForm(false);
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/favourites/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.favourites() });
    },
  });

  const handleMove = (index: number, direction: 'up' | 'down') => {
    const swapIndex = direction === 'up' ? index - 1 : index + 1;
    if (swapIndex < 0 || swapIndex >= favourites.length) return;

    const reordered = favourites.map((fav, i) => {
      if (i === index) return { id: fav.id, sort_order: swapIndex };
      if (i === swapIndex) return { id: fav.id, sort_order: index };
      return { id: fav.id, sort_order: i };
    });

    reorderMutation.mutate(reordered);
  };

  const handleUseFavourite = (code: string) => {
    // Navigate to claim page with code pre-filled via search params
    router.push(`${ROUTES.MOBILE_CLAIM}?hsc=${encodeURIComponent(code)}`);
  };

  const handleAddCode = (e: React.FormEvent) => {
    e.preventDefault();
    if (newCode.trim()) {
      addMutation.mutate(newCode.trim().toUpperCase());
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Favourites</h1>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowAddForm(!showAddForm)}
        >
          <Plus className="mr-1 h-4 w-4" />
          Add
        </Button>
      </div>

      {/* Add Code Form */}
      {showAddForm && (
        <Card>
          <CardContent className="pt-4">
            <form onSubmit={handleAddCode} className="flex gap-2">
              <input
                type="text"
                value={newCode}
                onChange={(e) => setNewCode(e.target.value.toUpperCase())}
                placeholder="HSC code (e.g. 03.05A)"
                className="flex-1 rounded-md border px-3 py-2 text-sm font-mono"
                autoFocus
              />
              <Button
                type="submit"
                size="sm"
                disabled={!newCode.trim() || addMutation.isPending}
              >
                {addMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  'Save'
                )}
              </Button>
            </form>
            {addMutation.isError && (
              <p className="mt-2 text-xs text-destructive">
                {addMutation.error instanceof Error
                  ? addMutation.error.message
                  : 'Failed to add code'}
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : favourites.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-10">
            <Star className="h-10 w-10 text-muted-foreground/40" />
            <p className="text-sm text-muted-foreground">No favourite codes yet</p>
            <p className="text-xs text-muted-foreground">
              Add frequently used HSC codes for quick access
            </p>
          </CardContent>
        </Card>
      ) : (
        /* Favourites Grid */
        <div className="grid grid-cols-1 gap-2">
          {favourites.map((fav, index) => (
            <Card
              key={fav.id}
              className={cn(
                'transition-colors',
                removeMutation.isPending && 'opacity-60'
              )}
            >
              <CardContent className="flex items-center gap-3 p-3">
                {/* Reorder Buttons */}
                <div className="flex flex-col gap-0.5">
                  <button
                    type="button"
                    onClick={() => handleMove(index, 'up')}
                    disabled={index === 0 || reorderMutation.isPending}
                    className="rounded p-0.5 hover:bg-muted disabled:opacity-30"
                    aria-label="Move up"
                  >
                    <ChevronUp className="h-4 w-4" />
                  </button>
                  <button
                    type="button"
                    onClick={() => handleMove(index, 'down')}
                    disabled={index === favourites.length - 1 || reorderMutation.isPending}
                    className="rounded p-0.5 hover:bg-muted disabled:opacity-30"
                    aria-label="Move down"
                  >
                    <ChevronDown className="h-4 w-4" />
                  </button>
                </div>

                {/* Code Info - tappable */}
                <button
                  type="button"
                  className="flex-1 text-left min-w-0"
                  onClick={() => handleUseFavourite(fav.health_service_code)}
                >
                  <p className="text-sm font-mono font-semibold">
                    {fav.health_service_code}
                  </p>
                  <p className="text-xs text-muted-foreground truncate">
                    {fav.description}
                  </p>
                </button>

                {/* Remove */}
                <button
                  type="button"
                  onClick={() => removeMutation.mutate(fav.id)}
                  disabled={removeMutation.isPending}
                  className="rounded p-1.5 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                  aria-label={`Remove ${fav.health_service_code}`}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
