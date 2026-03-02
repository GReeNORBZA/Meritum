'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { accountDeleteSchema } from '@meritum/shared';
import type { AccountDelete } from '@meritum/shared';
import { api } from '@/lib/api/client';
import { useAuthStore } from '@/stores/auth.store';
import { useRouter } from 'next/navigation';
import { ROUTES } from '@/config/routes';
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Loader2, AlertTriangle } from 'lucide-react';

export function AccountDeletionDialog() {
  const router = useRouter();
  const { logout } = useAuthStore();
  const [error, setError] = useState('');
  const [open, setOpen] = useState(false);

  const form = useForm<AccountDelete>({
    resolver: zodResolver(accountDeleteSchema),
    defaultValues: { password: '', totp_code: '', confirmation: '' as unknown as 'DELETE' },
  });

  const onSubmit = async (data: AccountDelete) => {
    setError('');
    try {
      await api.post('/api/v1/account/delete', data);
      logout();
      router.push(ROUTES.LOGIN);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete account';
      setError(message);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button variant="destructive">Delete Account</Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Delete Account
          </AlertDialogTitle>
          <AlertDialogDescription>
            This action is permanent and cannot be undone. All your data will be permanently deleted.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {error && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
        )}
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="delete-password">Current Password</Label>
            <Input id="delete-password" type="password" {...form.register('password')} />
            {form.formState.errors.password && (
              <p className="text-xs text-destructive">{form.formState.errors.password.message}</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="delete-totp">Authentication Code</Label>
            <Input
              id="delete-totp"
              placeholder="000000"
              maxLength={6}
              inputMode="numeric"
              className="font-mono"
              {...form.register('totp_code')}
            />
            {form.formState.errors.totp_code && (
              <p className="text-xs text-destructive">{form.formState.errors.totp_code.message}</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="delete-confirm">Type DELETE to confirm</Label>
            <Input id="delete-confirm" placeholder="DELETE" {...form.register('confirmation')} />
            {form.formState.errors.confirmation && (
              <p className="text-xs text-destructive">{form.formState.errors.confirmation.message}</p>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button type="submit" variant="destructive" disabled={form.formState.isSubmitting}>
              {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Permanently Delete
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  );
}
