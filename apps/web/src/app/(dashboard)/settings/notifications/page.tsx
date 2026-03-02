'use client';

import { useEffect, useState } from 'react';
import {
  useNotificationPreferences,
  useUpdateNotificationPreferences,
  type NotificationPreferences,
  type QuietHoursConfig,
} from '@/hooks/api/use-notifications';
import { QuietHoursForm } from '@/components/domain/notifications/quiet-hours-form';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import { Loader2, Bell, Mail, Smartphone, Moon } from 'lucide-react';

// ---------- Types ----------

type CategoryKey = 'claims' | 'billing' | 'system';

interface CategoryConfig {
  key: CategoryKey;
  label: string;
  description: string;
}

// ---------- Constants ----------

const CATEGORIES: CategoryConfig[] = [
  {
    key: 'claims',
    label: 'Claims',
    description: 'Claim status changes, rejections, and assessments',
  },
  {
    key: 'billing',
    label: 'Billing',
    description: 'Batch submissions, payment confirmations, and reconciliation',
  },
  {
    key: 'system',
    label: 'System',
    description: 'SOMB updates, maintenance notices, and account alerts',
  },
];

// ---------- Component ----------

export default function NotificationPreferencesPage() {
  const { data, isLoading } = useNotificationPreferences();
  const updatePreferences = useUpdateNotificationPreferences();

  const preferences = data?.data;

  const [localPrefs, setLocalPrefs] = useState<NotificationPreferences | null>(null);

  // Sync state when data loads
  useEffect(() => {
    if (preferences) {
      setLocalPrefs(preferences);
    }
  }, [preferences]);

  const handleCategoryToggle = (category: CategoryKey, checked: boolean) => {
    if (!localPrefs) return;
    const updated: NotificationPreferences = {
      ...localPrefs,
      categories: {
        ...localPrefs.categories,
        [category]: checked,
      },
    };
    setLocalPrefs(updated);
    updatePreferences.mutate({ categories: updated.categories });
  };

  const handleChannelToggle = (
    category: CategoryKey,
    channel: 'in_app' | 'email',
    checked: boolean
  ) => {
    if (!localPrefs) return;
    const updated: NotificationPreferences = {
      ...localPrefs,
      channels: {
        ...localPrefs.channels,
        [category]: {
          ...localPrefs.channels[category],
          [channel]: checked,
        },
      },
    };
    setLocalPrefs(updated);
    updatePreferences.mutate({ channels: updated.channels });
  };

  const handleQuietHoursChange = (quietHours: QuietHoursConfig) => {
    if (!localPrefs) return;
    const updated: NotificationPreferences = {
      ...localPrefs,
      quiet_hours: quietHours,
    };
    setLocalPrefs(updated);
    updatePreferences.mutate({ quiet_hours: quietHours });
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Notifications</h2>
          <p className="text-muted-foreground">
            Manage how and when you receive notifications
          </p>
        </div>
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-72" />
          </CardHeader>
          <CardContent className="space-y-6">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!localPrefs) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Notifications</h2>
          <p className="text-muted-foreground">
            Manage how and when you receive notifications
          </p>
        </div>
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-sm text-muted-foreground">
              Unable to load notification preferences. Please try again later.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Notifications</h2>
        <p className="text-muted-foreground">
          Manage how and when you receive notifications
        </p>
      </div>

      {/* Category & Channel Preferences */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Notification Categories
          </CardTitle>
          <CardDescription>
            Enable or disable notification categories and choose delivery channels
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {CATEGORIES.map((cat, index) => (
            <div key={cat.key}>
              {index > 0 && <Separator className="mb-6" />}

              {/* Category toggle */}
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-sm font-medium">{cat.label}</Label>
                  <p className="text-xs text-muted-foreground">{cat.description}</p>
                </div>
                <Switch
                  checked={localPrefs.categories[cat.key]}
                  onCheckedChange={(checked) => handleCategoryToggle(cat.key, checked)}
                  disabled={updatePreferences.isPending}
                />
              </div>

              {/* Channel toggles (only shown if category is enabled) */}
              {localPrefs.categories[cat.key] && (
                <div className="mt-3 ml-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Smartphone className="h-3.5 w-3.5 text-muted-foreground" />
                      <Label className="text-sm font-normal">In-app notifications</Label>
                    </div>
                    <Switch
                      checked={localPrefs.channels[cat.key].in_app}
                      onCheckedChange={(checked) =>
                        handleChannelToggle(cat.key, 'in_app', checked)
                      }
                      disabled={updatePreferences.isPending}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Mail className="h-3.5 w-3.5 text-muted-foreground" />
                      <Label className="text-sm font-normal">Email notifications</Label>
                    </div>
                    <Switch
                      checked={localPrefs.channels[cat.key].email}
                      onCheckedChange={(checked) =>
                        handleChannelToggle(cat.key, 'email', checked)
                      }
                      disabled={updatePreferences.isPending}
                    />
                  </div>
                </div>
              )}
            </div>
          ))}

          {updatePreferences.isPending && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Saving preferences...
            </div>
          )}
        </CardContent>
      </Card>

      {/* Quiet Hours */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Moon className="h-5 w-5" />
            Quiet Hours
          </CardTitle>
          <CardDescription>
            Pause notifications during specific hours to minimize interruptions
          </CardDescription>
        </CardHeader>
        <CardContent>
          <QuietHoursForm
            value={localPrefs.quiet_hours}
            onChange={handleQuietHoursChange}
            disabled={updatePreferences.isPending}
          />
        </CardContent>
      </Card>
    </div>
  );
}
