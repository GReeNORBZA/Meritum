'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Mail, Loader2 } from 'lucide-react';

function VerifyEmailPageContent() {
  const searchParams = useSearchParams();
  const email = searchParams.get('email');
  const token = searchParams.get('token');
  const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | 'verified' | 'error'>('idle');
  const [error, setError] = useState('');

  // If there's a token in URL, verify it automatically
  useEffect(() => {
    if (token) {
      api.post('/api/v1/auth/verify-email', { token })
        .then(() => setStatus('verified'))
        .catch((err: any) => { setError(err?.message || 'Verification failed'); setStatus('error'); });
    }
  }, [token]);

  const handleResend = async () => {
    if (!email) return;
    setStatus('sending');
    try {
      await api.post('/api/v1/auth/verify-email/resend', { email });
      setStatus('sent');
    } catch (err: any) {
      setError(err?.message || 'Failed to resend');
      setStatus('error');
    }
  };

  if (status === 'verified') {
    return (
      <Card>
        <CardHeader className="text-center">
          <CardTitle>Email Verified</CardTitle>
          <CardDescription>Your email has been verified. You can now sign in.</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center">
          <Link href={ROUTES.LOGIN}>
            <Button>Sign in</Button>
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
          <Mail className="h-6 w-6 text-primary" />
        </div>
        <CardTitle>Check your email</CardTitle>
        <CardDescription>
          {email ? (
            <>We sent a verification link to <strong>{email}</strong></>
          ) : (
            'We sent a verification link to your email address'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
        )}
        {status === 'sent' && (
          <div className="rounded-md bg-success/10 p-3 text-sm text-success">Verification email resent!</div>
        )}
        <div className="text-center text-sm text-muted-foreground">
          Didn&apos;t receive the email? Check your spam folder or{' '}
          <button onClick={handleResend} disabled={status === 'sending'} className="text-primary hover:underline inline-flex items-center">
            {status === 'sending' && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
            resend it
          </button>
        </div>
        <div className="text-center">
          <Link href={ROUTES.LOGIN} className="text-sm text-muted-foreground hover:underline">
            Back to sign in
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense>
      <VerifyEmailPageContent />
    </Suspense>
  );
}
