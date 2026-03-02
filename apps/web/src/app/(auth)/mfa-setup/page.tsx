'use client';

import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { mfaConfirmSchema } from '@meritum/shared';
import type { MfaConfirm } from '@meritum/shared';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2, Copy, Download, Shield, Check } from 'lucide-react';

type SetupStep = 'qr' | 'confirm' | 'recovery';

export default function MfaSetupPage() {
  const router = useRouter();
  const [step, setStep] = useState<SetupStep>('qr');
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const form = useForm<MfaConfirm>({
    resolver: zodResolver(mfaConfirmSchema),
    defaultValues: { totp_code: '' },
  });

  useEffect(() => {
    api.get<{ data: { qr_code_url: string; secret: string } }>('/api/v1/auth/mfa/setup')
      .then((res) => {
        setQrCodeUrl(res.data.qr_code_url);
        setSecret(res.data.secret);
      })
      .catch((err: any) => setError(err?.message || 'Failed to load MFA setup'));
  }, []);

  const onConfirm = async (data: MfaConfirm) => {
    setError('');
    try {
      const res = await api.post<{ data: { recovery_codes: string[] } }>('/api/v1/auth/mfa/confirm', data);
      setRecoveryCodes(res.data.recovery_codes);
      setStep('recovery');
    } catch (err: any) {
      setError(err?.message || 'Invalid code');
    }
  };

  const copyRecoveryCodes = () => {
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadRecoveryCodes = () => {
    const blob = new Blob([recoveryCodes.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'meritum-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
          <Shield className="h-6 w-6 text-primary" />
        </div>
        <CardTitle>
          {step === 'recovery' ? 'Save Recovery Codes' : 'Set Up Two-Factor Authentication'}
        </CardTitle>
        <CardDescription>
          {step === 'qr' && 'Scan the QR code with your authenticator app'}
          {step === 'confirm' && 'Enter the 6-digit code to verify'}
          {step === 'recovery' && 'Store these codes safely. Each can be used once if you lose access to your authenticator.'}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
        )}

        {step === 'qr' && (
          <>
            {qrCodeUrl ? (
              <div className="flex justify-center">
                <img src={qrCodeUrl} alt="MFA QR Code" className="h-48 w-48" />
              </div>
            ) : (
              <div className="flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
            )}
            {secret && (
              <div className="text-center">
                <p className="text-xs text-muted-foreground mb-1">Or enter this code manually:</p>
                <code className="text-sm font-mono bg-muted px-3 py-1 rounded">{secret}</code>
              </div>
            )}
            <Button className="w-full" onClick={() => setStep('confirm')} disabled={!qrCodeUrl}>
              I&apos;ve scanned the code
            </Button>
          </>
        )}

        {step === 'confirm' && (
          <form onSubmit={form.handleSubmit(onConfirm)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="totp_code">Verification Code</Label>
              <Input
                id="totp_code"
                placeholder="000000"
                maxLength={6}
                inputMode="numeric"
                className="text-center text-2xl tracking-widest font-mono"
                {...form.register('totp_code')}
              />
              {form.formState.errors.totp_code && (
                <p className="text-xs text-destructive">{form.formState.errors.totp_code.message}</p>
              )}
            </div>
            <Button type="submit" className="w-full" disabled={form.formState.isSubmitting}>
              {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Verify & Enable
            </Button>
            <Button type="button" variant="ghost" className="w-full" onClick={() => setStep('qr')}>
              Back to QR code
            </Button>
          </form>
        )}

        {step === 'recovery' && (
          <>
            <div className="grid grid-cols-2 gap-2 rounded-md bg-muted p-4">
              {recoveryCodes.map((code) => (
                <code key={code} className="text-sm font-mono text-center py-1">{code}</code>
              ))}
            </div>
            <div className="flex gap-2">
              <Button variant="outline" className="flex-1" onClick={copyRecoveryCodes}>
                {copied ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
                {copied ? 'Copied' : 'Copy'}
              </Button>
              <Button variant="outline" className="flex-1" onClick={downloadRecoveryCodes}>
                <Download className="mr-2 h-4 w-4" />
                Download
              </Button>
            </div>
            <Button className="w-full" onClick={() => router.push(ROUTES.DASHBOARD)}>
              I&apos;ve saved my codes - Continue
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}
