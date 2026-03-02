'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Users, Crown } from 'lucide-react';

interface PracticeMember {
  id: string;
  full_name: string;
  email: string;
  role: string;
  status: string;
}

interface PracticeData {
  name: string;
  seat_limit: number;
  seats_used: number;
  members: PracticeMember[];
}

export default function PracticePage() {
  const { data, isLoading } = useQuery({
    queryKey: queryKeys.subscription.practice(),
    queryFn: () => api.get<{ data: PracticeData }>('/api/v1/subscription/practice'),
  });

  const practice = data?.data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Practice Management</h1>
        <p className="text-muted-foreground">Manage your practice members and seat allocation</p>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-48" />
        </div>
      ) : practice ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{practice.name}</CardTitle>
              <CardDescription>
                {practice.seats_used} of {practice.seat_limit} seats used
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-2 w-full rounded-full bg-secondary">
                <div
                  className="h-2 rounded-full bg-primary transition-all"
                  style={{ width: `${Math.min((practice.seats_used / practice.seat_limit) * 100, 100)}%` }}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                Members
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {practice.members.map((member) => (
                  <div key={member.id} className="flex items-center justify-between rounded-md border p-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 text-sm font-medium text-primary">
                        {member.full_name.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium flex items-center gap-1.5">
                          {member.full_name}
                          {member.role === 'admin' && <Crown className="h-3.5 w-3.5 text-warning" />}
                        </p>
                        <p className="text-xs text-muted-foreground">{member.email}</p>
                      </div>
                    </div>
                    <Badge variant={member.status === 'active' ? 'success' : 'secondary'}>
                      {member.role}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </>
      ) : (
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-muted-foreground">Practice information is not available.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
