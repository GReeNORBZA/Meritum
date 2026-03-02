'use client';

import { useState, Suspense } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { passwordResetSchema } from '@meritum/shared';
import type { PasswordReset } from '@meritum/shared';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2 } from 'lucide-react';

function ResetPasswordPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token') || '';
  const [error, setError] = useState('');

  const form = useForm<PasswordReset>({
    resolver: zodResolver(passwordResetSchema),
    defaultValues: { token, new_password: '' },
  });

  const onSubmit = async (data: PasswordReset) => {
    setError('');
    try {
      await api.post('/api/v1/auth/password-reset', data);
      router.push(`${ROUTES.LOGIN}?reset=success`);
    } catch (err: any) {
      setError(err?.message || 'Failed to reset password');
    }
  };

  if (!token) {
    return (
      <Card>
        <CardHeader className="text-center">
          <CardTitle>Invalid Link</CardTitle>
          <CardDescription>This password reset link is invalid or expired.</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center">
          <Link href={ROUTES.FORGOT_PASSWORD}>
            <Button>Request a new link</Button>
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Reset your password</CardTitle>
        <CardDescription>Enter a new password for your account</CardDescription>
      </CardHeader>
      <CardContent>
        {error && (
          <div className="mb-4 rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
        )}
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="new_password">New Password</Label>
            <Input id="new_password" type="password" {...form.register('new_password')} />
            {form.formState.errors.new_password && (
              <p className="text-xs text-destructive">{form.formState.errors.new_password.message}</p>
            )}
            <p className="text-xs text-muted-foreground">Minimum 12 characters with uppercase, lowercase, number, and special character</p>
          </div>
          <Button type="submit" className="w-full" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Reset password
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordPageContent />
    </Suspense>
  );
}
