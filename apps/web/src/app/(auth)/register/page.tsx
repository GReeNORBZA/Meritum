'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { registerSchema } from '@meritum/shared';
import type { Register } from '@meritum/shared';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useState } from 'react';
import { api } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2 } from 'lucide-react';

function getPasswordStrength(password: string): { score: number; label: string } {
  let score = 0;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z\d]/.test(password)) score++;
  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
  return { score, label: labels[Math.min(score, 4)] ?? 'Very weak' };
}

const strengthColors = ['bg-destructive', 'bg-destructive', 'bg-warning', 'bg-primary', 'bg-success'];

export default function RegisterPage() {
  const router = useRouter();
  const [error, setError] = useState('');
  const form = useForm<Register>({
    resolver: zodResolver(registerSchema),
    defaultValues: { email: '', password: '', full_name: '', phone: '' },
  });

  const password = form.watch('password');
  const strength = getPasswordStrength(password || '');

  const onSubmit = async (data: Register) => {
    setError('');
    try {
      await api.post('/api/v1/auth/register', data);
      router.push(`${ROUTES.VERIFY_EMAIL}?email=${encodeURIComponent(data.email)}`);
    } catch (err: any) {
      setError(err?.message || 'Registration failed');
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create an account</CardTitle>
        <CardDescription>Enter your details to get started with Meritum</CardDescription>
      </CardHeader>
      <CardContent>
        {error && (
          <div className="mb-4 rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
        )}
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="full_name">Full Name</Label>
            <Input id="full_name" placeholder="Dr. Jane Smith" {...form.register('full_name')} />
            {form.formState.errors.full_name && (
              <p className="text-xs text-destructive">{form.formState.errors.full_name.message}</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" placeholder="you@example.com" {...form.register('email')} />
            {form.formState.errors.email && (
              <p className="text-xs text-destructive">{form.formState.errors.email.message}</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input id="password" type="password" {...form.register('password')} />
            {password && (
              <div className="space-y-1">
                <div className="flex gap-1">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className={`h-1.5 flex-1 rounded-full ${i < strength.score ? strengthColors[strength.score - 1] : 'bg-muted'}`} />
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">{strength.label}</p>
              </div>
            )}
            {form.formState.errors.password && (
              <p className="text-xs text-destructive">{form.formState.errors.password.message}</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="phone">Phone (optional)</Label>
            <Input id="phone" type="tel" placeholder="+1 (403) 555-0123" {...form.register('phone')} />
          </div>
          <Button type="submit" className="w-full" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Create account
          </Button>
        </form>
      </CardContent>
      <CardFooter className="flex justify-center">
        <p className="text-sm text-muted-foreground">
          Already have an account?{' '}
          <Link href={ROUTES.LOGIN} className="text-primary hover:underline">Sign in</Link>
        </p>
      </CardFooter>
    </Card>
  );
}
