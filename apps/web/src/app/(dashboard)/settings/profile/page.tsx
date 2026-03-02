'use client';

import { useEffect, useState } from 'react';
import { useProviderProfile, useUpdateProviderProfile } from '@/hooks/api/use-providers';
import { useAccountDelete } from '@/hooks/api/use-auth';
import { useAuthStore } from '@/stores/auth.store';
import { useRouter } from 'next/navigation';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Loader2, AlertTriangle } from 'lucide-react';

const SPECIALTY_OPTIONS = [
  { value: '00', label: 'General Practice' },
  { value: '01', label: 'Internal Medicine' },
  { value: '02', label: 'Pediatrics' },
  { value: '03', label: 'General Surgery' },
  { value: '04', label: 'Obstetrics/Gynecology' },
  { value: '05', label: 'Psychiatry' },
  { value: '06', label: 'Anesthesia' },
  { value: '07', label: 'Pathology' },
  { value: '08', label: 'Radiology' },
  { value: '09', label: 'Emergency Medicine' },
];

const PHYSICIAN_TYPE_OPTIONS = [
  { value: 'GP', label: 'General Practitioner' },
  { value: 'SPECIALIST', label: 'Specialist' },
  { value: 'LOCUM', label: 'Locum' },
];

export default function ProfilePage() {
  const { data, isLoading } = useProviderProfile();
  const updateProfile = useUpdateProviderProfile();
  const deleteAccount = useAccountDelete();
  const { logout } = useAuthStore();
  const router = useRouter();

  const profile = data?.data;

  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [specialtyCode, setSpecialtyCode] = useState('');
  const [physicianType, setPhysicianType] = useState('');
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteTotpCode, setDeleteTotpCode] = useState('');
  const [deleteConfirmation, setDeleteConfirmation] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (profile) {
      setFirstName(profile.first_name);
      setLastName(profile.last_name);
      setSpecialtyCode(profile.specialty_code);
      setPhysicianType(profile.physician_type);
    }
  }, [profile]);

  const validateProfile = () => {
    const newErrors: Record<string, string> = {};
    if (!firstName.trim()) newErrors.first_name = 'First name is required';
    if (!lastName.trim()) newErrors.last_name = 'Last name is required';
    if (!specialtyCode) newErrors.specialty_code = 'Specialty is required';
    if (!physicianType) newErrors.physician_type = 'Physician type is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateProfile()) return;
    updateProfile.mutate({
      first_name: firstName,
      last_name: lastName,
      specialty_code: specialtyCode,
      physician_type: physicianType,
    });
  };

  const handleDeleteAccount = () => {
    if (deleteConfirmation !== 'DELETE') return;
    deleteAccount.mutate(
      { password: deletePassword, totp_code: deleteTotpCode, confirmation: 'DELETE' },
      {
        onSuccess: () => {
          logout();
          router.push(ROUTES.LOGIN);
        },
      }
    );
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Profile</h2>
          <p className="text-muted-foreground">Manage your provider profile information</p>
        </div>
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-72" />
          </CardHeader>
          <CardContent className="space-y-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Profile</h2>
        <p className="text-muted-foreground">Manage your provider profile information</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Provider Information</CardTitle>
          <CardDescription>Update your personal and professional details</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="first_name">First Name</Label>
                <Input
                  id="first_name"
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                />
                {errors.first_name && (
                  <p className="text-sm text-destructive">{errors.first_name}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="last_name">Last Name</Label>
                <Input
                  id="last_name"
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                />
                {errors.last_name && (
                  <p className="text-sm text-destructive">{errors.last_name}</p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" value={profile?.email ?? ''} disabled />
              <p className="text-xs text-muted-foreground">
                Email cannot be changed. Contact support if you need to update it.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="billing_number">Billing Number (Prac ID)</Label>
              <Input id="billing_number" value={profile?.billing_number ?? ''} disabled />
              <p className="text-xs text-muted-foreground">
                Billing number is assigned by Alberta Health and cannot be modified here.
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="specialty_code">Specialty</Label>
                <Select value={specialtyCode} onValueChange={setSpecialtyCode}>
                  <SelectTrigger id="specialty_code">
                    <SelectValue placeholder="Select specialty" />
                  </SelectTrigger>
                  <SelectContent>
                    {SPECIALTY_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.value} - {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.specialty_code && (
                  <p className="text-sm text-destructive">{errors.specialty_code}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="physician_type">Physician Type</Label>
                <Select value={physicianType} onValueChange={setPhysicianType}>
                  <SelectTrigger id="physician_type">
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    {PHYSICIAN_TYPE_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.physician_type && (
                  <p className="text-sm text-destructive">{errors.physician_type}</p>
                )}
              </div>
            </div>

            <div className="flex justify-end">
              <Button type="submit" disabled={updateProfile.isPending}>
                {updateProfile.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Changes
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Separator />

      <Card className="border-destructive">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="h-5 w-5" />
            Danger Zone
          </CardTitle>
          <CardDescription>
            Permanently delete your account and all associated data. This action cannot be undone.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive">Delete Account</Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                <AlertDialogDescription>
                  This will permanently delete your account, all claims, patient records, and
                  associated data. This action cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <div className="space-y-4 py-2">
                <div className="space-y-2">
                  <Label htmlFor="delete_password">Password</Label>
                  <Input
                    id="delete_password"
                    type="password"
                    value={deletePassword}
                    onChange={(e) => setDeletePassword(e.target.value)}
                    placeholder="Enter your password"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="delete_totp">MFA Code</Label>
                  <Input
                    id="delete_totp"
                    value={deleteTotpCode}
                    onChange={(e) => setDeleteTotpCode(e.target.value)}
                    placeholder="Enter your 6-digit code"
                    maxLength={6}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="delete_confirm">
                    Type <span className="font-mono font-bold">DELETE</span> to confirm
                  </Label>
                  <Input
                    id="delete_confirm"
                    value={deleteConfirmation}
                    onChange={(e) => setDeleteConfirmation(e.target.value)}
                    placeholder="DELETE"
                  />
                </div>
              </div>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={handleDeleteAccount}
                  disabled={
                    deleteConfirmation !== 'DELETE' ||
                    !deletePassword ||
                    !deleteTotpCode ||
                    deleteAccount.isPending
                  }
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                >
                  {deleteAccount.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Delete Account
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardContent>
      </Card>
    </div>
  );
}
