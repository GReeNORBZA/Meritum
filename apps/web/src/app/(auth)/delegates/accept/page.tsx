'use client';

import { useState, useEffect, Suspense } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { delegateAcceptSchema } from '@meritum/shared';
import type { DelegateAccept } from '@meritum/shared';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2, Users } from 'lucide-react';

interface InviteInfo {
  physician_name: string;
  permissions: string[];
  is_existing_user: boolean;
}

function DelegateAcceptPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token') || '';
  const [inviteInfo, setInviteInfo] = useState<InviteInfo | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const form = useForm<DelegateAccept>({
    resolver: zodResolver(delegateAcceptSchema),
    defaultValues: { token, full_name: '', password: '' },
  });

  useEffect(() => {
    if (!token) { setLoading(false); return; }
    api.get<{ data: InviteInfo }>(`/api/v1/delegates/invite?token=${token}`)
      .then((res) => setInviteInfo(res.data))
      .catch((err: any) => setError(err?.message || 'Invalid invitation'))
      .finally(() => setLoading(false));
  }, [token]);

  const onSubmit = async (data: DelegateAccept) => {
    setError('');
    try {
      await api.post('/api/v1/delegates/accept', data);
      router.push(`${ROUTES.LOGIN}?delegate=accepted`);
    } catch (err: any) {
      setError(err?.message || 'Failed to accept invitation');
    }
  };

  if (!token) {
    return (
      <Card>
        <CardHeader className="text-center">
          <CardTitle>Invalid Invitation</CardTitle>
          <CardDescription>This invitation link is invalid or expired.</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center">
          <Link href={ROUTES.LOGIN}><Button>Go to sign in</Button></Link>
        </CardContent>
      </Card>
    );
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="flex justify-center py-8">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
          <Users className="h-6 w-6 text-primary" />
        </div>
        <CardTitle>Delegate Invitation</CardTitle>
        <CardDescription>
          {inviteInfo
            ? `${inviteInfo.physician_name} has invited you as a delegate`
            : 'You have been invited as a delegate'}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {error && (
          <div className="mb-4 rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
        )}
        {inviteInfo?.permissions && (
          <div className="mb-4 rounded-md bg-muted p-3">
            <p className="text-sm font-medium mb-2">Permissions granted:</p>
            <ul className="text-sm text-muted-foreground space-y-1">
              {inviteInfo.permissions.map((p) => (
                <li key={p}>{p.replace(/_/g, ' ').toLowerCase()}</li>
              ))}
            </ul>
          </div>
        )}
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          {!inviteInfo?.is_existing_user && (
            <>
              <div className="space-y-2">
                <Label htmlFor="full_name">Full Name</Label>
                <Input id="full_name" placeholder="Jane Smith" {...form.register('full_name')} />
                {form.formState.errors.full_name && (
                  <p className="text-xs text-destructive">{form.formState.errors.full_name.message}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input id="password" type="password" {...form.register('password')} />
                {form.formState.errors.password && (
                  <p className="text-xs text-destructive">{form.formState.errors.password.message}</p>
                )}
                <p className="text-xs text-muted-foreground">Minimum 12 characters with uppercase, lowercase, number, and special character</p>
              </div>
            </>
          )}
          <Button type="submit" className="w-full" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Accept Invitation
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

export default function DelegateAcceptPage() {
  return (
    <Suspense>
      <DelegateAcceptPageContent />
    </Suspense>
  );
}
