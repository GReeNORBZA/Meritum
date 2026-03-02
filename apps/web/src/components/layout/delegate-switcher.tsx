'use client';

import { useAuthStore } from '@/stores/auth.store';
import {
  useDelegatePhysicians,
  useSwitchDelegateContext,
  useClearDelegateContext,
} from '@/hooks/api/use-delegates';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { ChevronDown, UserCheck, Users, X, Loader2 } from 'lucide-react';

export function DelegateSwitcher() {
  const { user, delegateContext } = useAuthStore();
  const { data, isLoading } = useDelegatePhysicians();
  const switchContext = useSwitchDelegateContext();
  const clearContext = useClearDelegateContext();

  // Only render for delegates
  if (user?.role !== 'delegate') return null;

  const physicians = data?.data ?? [];

  if (isLoading) {
    return <Skeleton className="h-9 w-40" />;
  }

  if (physicians.length === 0) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Users className="h-4 w-4" />
        <span>No physician access</span>
      </div>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="gap-2">
          {delegateContext ? (
            <>
              <UserCheck className="h-4 w-4" />
              <span className="max-w-[150px] truncate">{delegateContext.physicianName}</span>
            </>
          ) : (
            <>
              <Users className="h-4 w-4" />
              <span>Select Physician</span>
            </>
          )}
          <ChevronDown className="h-3 w-3 opacity-50" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel>Switch Physician Context</DropdownMenuLabel>
        <DropdownMenuSeparator />

        {physicians.map((physician) => {
          const isActive = delegateContext?.physicianProviderId === physician.provider_id;
          return (
            <DropdownMenuItem
              key={physician.provider_id}
              onClick={() => {
                if (!isActive) {
                  switchContext.mutate(physician.provider_id);
                }
              }}
              disabled={switchContext.isPending}
              className="flex items-center justify-between"
            >
              <div className="flex flex-col">
                <span className="font-medium">{physician.physician_name}</span>
                <span className="text-xs text-muted-foreground">
                  Prac #{physician.billing_number}
                </span>
              </div>
              {isActive && <Badge variant="success" className="ml-2 text-xs">Active</Badge>}
              {switchContext.isPending && (
                <Loader2 className="ml-2 h-3 w-3 animate-spin" />
              )}
            </DropdownMenuItem>
          );
        })}

        {delegateContext && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => clearContext.mutate()}
              disabled={clearContext.isPending}
              className="text-muted-foreground"
            >
              <X className="mr-2 h-4 w-4" />
              Clear Context
              {clearContext.isPending && (
                <Loader2 className="ml-auto h-3 w-3 animate-spin" />
              )}
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
