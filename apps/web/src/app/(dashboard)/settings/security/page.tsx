'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { useRevokeSession, useRevokeAllSessions } from '@/hooks/api/use-auth';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import { Monitor, Smartphone, Shield, Loader2, X } from 'lucide-react';
import { formatRelative } from '@/lib/formatters/date';

interface Session {
  id: string;
  ip_address: string;
  user_agent: string;
  last_active_at: string;
  created_at: string;
  is_current: boolean;
}

export default function SecurityPage() {
  const { data, isLoading } = useQuery({
    queryKey: queryKeys.auth.sessions(),
    queryFn: () => api.get<{ data: Session[] }>('/api/v1/sessions'),
  });

  const revokeSession = useRevokeSession();
  const revokeAll = useRevokeAllSessions();

  const sessions = data?.data ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Security</h1>
        <p className="text-muted-foreground">Manage your sessions and security settings</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Active Sessions</CardTitle>
              <CardDescription>Devices currently signed in to your account</CardDescription>
            </div>
            {sessions.length > 1 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => revokeAll.mutate()}
                disabled={revokeAll.isPending}
              >
                {revokeAll.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Revoke all others
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-16" />
              ))}
            </div>
          ) : (
            <div className="space-y-4">
              {sessions.map((session) => (
                <div key={session.id} className="flex items-center justify-between rounded-lg border p-4">
                  <div className="flex items-center gap-4">
                    {session.user_agent?.includes('Mobile') ? (
                      <Smartphone className="h-5 w-5 text-muted-foreground" />
                    ) : (
                      <Monitor className="h-5 w-5 text-muted-foreground" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium">{session.user_agent || 'Unknown device'}</p>
                        {session.is_current && <Badge variant="success">Current</Badge>}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {session.ip_address} &middot; Last active {formatRelative(session.last_active_at)}
                      </p>
                    </div>
                  </div>
                  {!session.is_current && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => revokeSession.mutate(session.id)}
                      disabled={revokeSession.isPending}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Two-Factor Authentication
          </CardTitle>
          <CardDescription>Add an extra layer of security to your account</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Two-factor authentication is configured during account setup. Contact support to reconfigure.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
