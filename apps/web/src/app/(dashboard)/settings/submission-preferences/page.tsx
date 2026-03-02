'use client';

import { useEffect, useState } from 'react';
import {
  useSubmissionPreferences,
  useUpdateSubmissionPreferences,
  type SubmissionPreferences,
} from '@/hooks/api/use-providers';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2, Send } from 'lucide-react';

const SUBMISSION_MODE_OPTIONS = [
  { value: 'AUTO_CLEAN', label: 'Auto-submit clean claims' },
  { value: 'AUTO_ALL', label: 'Auto-submit all claims' },
  { value: 'REQUIRE_APPROVAL', label: 'Require manual approval' },
] as const;

type SubmissionMode = SubmissionPreferences['ahcip_submission_mode'];

export default function SubmissionPreferencesPage() {
  const { data, isLoading } = useSubmissionPreferences();
  const updatePrefs = useUpdateSubmissionPreferences();

  const prefs = data?.data;

  const [ahcipMode, setAhcipMode] = useState<SubmissionMode>('REQUIRE_APPROVAL');
  const [wcbMode, setWcbMode] = useState<SubmissionMode>('REQUIRE_APPROVAL');
  const [batchReminder, setBatchReminder] = useState(true);
  const [deadlineDays, setDeadlineDays] = useState(7);
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (prefs) {
      setAhcipMode(prefs.ahcip_submission_mode);
      setWcbMode(prefs.wcb_submission_mode);
      setBatchReminder(prefs.batch_review_reminder);
      setDeadlineDays(prefs.deadline_reminder_days);
    }
  }, [prefs]);

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (deadlineDays < 1 || deadlineDays > 30) {
      newErrors.deadline_reminder_days = 'Deadline reminder must be between 1 and 30 days';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;
    updatePrefs.mutate({
      ahcip_submission_mode: ahcipMode,
      wcb_submission_mode: wcbMode,
      batch_review_reminder: batchReminder,
      deadline_reminder_days: deadlineDays,
    });
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Submission Preferences</h2>
          <p className="text-muted-foreground">Configure how your claims are submitted</p>
        </div>
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-72" />
          </CardHeader>
          <CardContent className="space-y-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Submission Preferences</h2>
        <p className="text-muted-foreground">Configure how your claims are submitted</p>
      </div>

      <form onSubmit={handleSubmit}>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Send className="h-5 w-5" />
              Claim Submission Settings
            </CardTitle>
            <CardDescription>
              Control how AHCIP and WCB claims are batched and submitted
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="ahcip_mode">AHCIP Submission Mode</Label>
              <Select value={ahcipMode} onValueChange={(v) => setAhcipMode(v as SubmissionMode)}>
                <SelectTrigger id="ahcip_mode">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SUBMISSION_MODE_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Determines when AHCIP claims are automatically added to submission batches.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="wcb_mode">WCB Submission Mode</Label>
              <Select value={wcbMode} onValueChange={(v) => setWcbMode(v as SubmissionMode)}>
                <SelectTrigger id="wcb_mode">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SUBMISSION_MODE_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Determines when WCB claims are automatically submitted.
              </p>
            </div>

            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label htmlFor="batch_reminder">Batch Review Reminder</Label>
                <p className="text-xs text-muted-foreground">
                  Receive a reminder to review pending batches before submission deadlines
                </p>
              </div>
              <Switch
                id="batch_reminder"
                checked={batchReminder}
                onCheckedChange={setBatchReminder}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="deadline_days">Deadline Reminder (days before)</Label>
              <Input
                id="deadline_days"
                type="number"
                min={1}
                max={30}
                value={deadlineDays}
                onChange={(e) => setDeadlineDays(Number(e.target.value))}
                className="w-32"
              />
              {errors.deadline_reminder_days && (
                <p className="text-sm text-destructive">{errors.deadline_reminder_days}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Number of days before the submission deadline to send a reminder (1-30).
              </p>
            </div>

            <div className="flex justify-end">
              <Button type="submit" disabled={updatePrefs.isPending}>
                {updatePrefs.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Preferences
              </Button>
            </div>
          </CardContent>
        </Card>
      </form>
    </div>
  );
}
