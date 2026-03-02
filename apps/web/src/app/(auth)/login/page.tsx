'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { loginSchema, loginMfaSchema, loginRecoverySchema } from '@meritum/shared';
import type { Login, LoginMfa, LoginRecovery } from '@meritum/shared';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2 } from 'lucide-react';
import { useAuthStore } from '@/stores/auth.store';

// Step type
type LoginStep = 'credentials' | 'mfa' | 'recovery';

export default function LoginPage() {
  const router = useRouter();
  const { setUser } = useAuthStore();
  const [step, setStep] = useState<LoginStep>('credentials');
  const [mfaSessionToken, setMfaSessionToken] = useState('');
  const [error, setError] = useState('');

  // Step 1: Credentials form
  const credentialsForm = useForm<Login>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  });

  // Step 2: MFA form
  const mfaForm = useForm<LoginMfa>({
    resolver: zodResolver(loginMfaSchema),
    defaultValues: { mfa_session_token: '', totp_code: '' },
  });

  // Step 2 alt: Recovery code form
  const recoveryForm = useForm<LoginRecovery>({
    resolver: zodResolver(loginRecoverySchema),
    defaultValues: { mfa_session_token: '', recovery_code: '' },
  });

  const onCredentialsSubmit = async (data: Login) => {
    setError('');
    try {
      const res = await api.post<{ data: { mfa_required?: boolean; mfa_session_token?: string; user?: Record<string, unknown> } }>('/api/v1/auth/login', data);
      if (res.data.mfa_required && res.data.mfa_session_token) {
        setMfaSessionToken(res.data.mfa_session_token);
        mfaForm.setValue('mfa_session_token', res.data.mfa_session_token);
        recoveryForm.setValue('mfa_session_token', res.data.mfa_session_token);
        setStep('mfa');
      } else {
        if (res.data.user) setUser(res.data.user as any);
        router.push(ROUTES.DASHBOARD);
      }
    } catch (err: any) {
      setError(err?.message || 'Invalid credentials');
    }
  };

  const onMfaSubmit = async (data: LoginMfa) => {
    setError('');
    try {
      const res = await api.post<{ data: { user: Record<string, unknown> } }>('/api/v1/auth/login/mfa', data);
      if (res.data.user) setUser(res.data.user as any);
      router.push(ROUTES.DASHBOARD);
    } catch (err: any) {
      setError(err?.message || 'Invalid code');
    }
  };

  const onRecoverySubmit = async (data: LoginRecovery) => {
    setError('');
    try {
      const res = await api.post<{ data: { user: Record<string, unknown> } }>('/api/v1/auth/login/recovery', data);
      if (res.data.user) setUser(res.data.user as any);
      router.push(ROUTES.DASHBOARD);
    } catch (err: any) {
      setError(err?.message || 'Invalid recovery code');
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{step === 'credentials' ? 'Sign in' : 'Two-Factor Authentication'}</CardTitle>
        <CardDescription>
          {step === 'credentials'
            ? 'Enter your credentials to access your account'
            : step === 'mfa'
            ? 'Enter the 6-digit code from your authenticator app'
            : 'Enter one of your recovery codes'}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {error && (
          <div className="mb-4 rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
        )}

        {step === 'credentials' && (
          <form onSubmit={credentialsForm.handleSubmit(onCredentialsSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" placeholder="you@example.com" {...credentialsForm.register('email')} />
              {credentialsForm.formState.errors.email && (
                <p className="text-xs text-destructive">{credentialsForm.formState.errors.email.message}</p>
              )}
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Password</Label>
                <Link href={ROUTES.FORGOT_PASSWORD} className="text-xs text-primary hover:underline">
                  Forgot password?
                </Link>
              </div>
              <Input id="password" type="password" {...credentialsForm.register('password')} />
              {credentialsForm.formState.errors.password && (
                <p className="text-xs text-destructive">{credentialsForm.formState.errors.password.message}</p>
              )}
            </div>
            <Button type="submit" className="w-full" disabled={credentialsForm.formState.isSubmitting}>
              {credentialsForm.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Sign in
            </Button>
          </form>
        )}

        {step === 'mfa' && (
          <form onSubmit={mfaForm.handleSubmit(onMfaSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="totp_code">Authentication Code</Label>
              <Input id="totp_code" placeholder="000000" maxLength={6} inputMode="numeric" className="text-center text-2xl tracking-widest font-mono" {...mfaForm.register('totp_code')} />
              {mfaForm.formState.errors.totp_code && (
                <p className="text-xs text-destructive">{mfaForm.formState.errors.totp_code.message}</p>
              )}
            </div>
            <Button type="submit" className="w-full" disabled={mfaForm.formState.isSubmitting}>
              {mfaForm.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Verify
            </Button>
            <Button type="button" variant="ghost" className="w-full" onClick={() => setStep('recovery')}>
              Use a recovery code instead
            </Button>
          </form>
        )}

        {step === 'recovery' && (
          <form onSubmit={recoveryForm.handleSubmit(onRecoverySubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="recovery_code">Recovery Code</Label>
              <Input id="recovery_code" placeholder="xxxx-xxxx-xxxx" className="font-mono" {...recoveryForm.register('recovery_code')} />
              {recoveryForm.formState.errors.recovery_code && (
                <p className="text-xs text-destructive">{recoveryForm.formState.errors.recovery_code.message}</p>
              )}
            </div>
            <Button type="submit" className="w-full" disabled={recoveryForm.formState.isSubmitting}>
              {recoveryForm.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Verify
            </Button>
            <Button type="button" variant="ghost" className="w-full" onClick={() => setStep('mfa')}>
              Use authenticator app instead
            </Button>
          </form>
        )}
      </CardContent>
      <CardFooter className="flex justify-center">
        <p className="text-sm text-muted-foreground">
          Don&apos;t have an account?{' '}
          <Link href={ROUTES.REGISTER} className="text-primary hover:underline">
            Sign up
          </Link>
        </p>
      </CardFooter>
    </Card>
  );
}
