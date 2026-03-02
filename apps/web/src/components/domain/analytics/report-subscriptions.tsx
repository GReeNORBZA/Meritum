'use client';

import * as React from 'react';
import {
  useReportSubscriptions,
  useCreateSubscription,
  useUpdateSubscription,
  useDeleteSubscription,
  type ReportSubscription,
  type CreateSubscriptionInput,
} from '@/hooks/api/use-analytics';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Plus, Trash2, Bell, Mail, Download } from 'lucide-react';

const REPORT_TYPES = [
  { value: 'revenue_summary', label: 'Revenue Summary' },
  { value: 'rejection_analysis', label: 'Rejection Analysis' },
  { value: 'aging_report', label: 'Aging Report' },
  { value: 'wcb_summary', label: 'WCB Summary' },
  { value: 'ai_coach_performance', label: 'AI Coach Performance' },
  { value: 'multi_site_comparison', label: 'Multi-Site Comparison' },
  { value: 'monthly_overview', label: 'Monthly Overview' },
  { value: 'annual_summary', label: 'Annual Summary' },
] as const;

const FREQUENCIES = [
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
] as const;

const DELIVERY_METHODS = [
  { value: 'email', label: 'Email', icon: Mail },
  { value: 'download', label: 'Download', icon: Download },
] as const;

export function ReportSubscriptions() {
  const { data, isLoading } = useReportSubscriptions();
  const [createDialogOpen, setCreateDialogOpen] = React.useState(false);

  const subscriptions = data?.data ?? [];

  if (isLoading) {
    return <ReportSubscriptionsSkeleton />;
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5" />
              Report Subscriptions
            </CardTitle>
            <CardDescription>
              Automatically generate and receive reports on a schedule
            </CardDescription>
          </div>
          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="mr-2 h-4 w-4" />
                New Subscription
              </Button>
            </DialogTrigger>
            <CreateSubscriptionDialog onClose={() => setCreateDialogOpen(false)} />
          </Dialog>
        </div>
      </CardHeader>
      <CardContent>
        {subscriptions.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <Bell className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">
              No report subscriptions yet. Create one to automatically receive reports.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {subscriptions.map((subscription) => (
              <SubscriptionRow key={subscription.id} subscription={subscription} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------- Subscription Row ----------

function SubscriptionRow({ subscription }: { subscription: ReportSubscription }) {
  const updateMutation = useUpdateSubscription();
  const deleteMutation = useDeleteSubscription();

  const reportLabel =
    REPORT_TYPES.find((r) => r.value === subscription.report_type)?.label ??
    subscription.report_type;

  const handleToggle = (checked: boolean) => {
    updateMutation.mutate({
      id: subscription.id,
      data: { is_active: checked },
    });
  };

  const handleDelete = () => {
    deleteMutation.mutate(subscription.id);
  };

  return (
    <div className="flex items-center justify-between rounded-lg border p-4">
      <div className="flex items-center gap-4">
        <Switch
          checked={subscription.is_active}
          onCheckedChange={handleToggle}
          disabled={updateMutation.isPending}
        />
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">{reportLabel}</span>
            <Badge variant="outline" className="text-xs capitalize">
              {subscription.frequency}
            </Badge>
            <Badge variant="secondary" className="text-xs capitalize">
              {subscription.delivery_method === 'email' ? (
                <Mail className="mr-1 h-3 w-3" />
              ) : (
                <Download className="mr-1 h-3 w-3" />
              )}
              {subscription.delivery_method}
            </Badge>
          </div>
          <div className="mt-1 flex gap-3 text-xs text-muted-foreground">
            {subscription.last_sent_at && (
              <span>Last sent: {new Date(subscription.last_sent_at).toLocaleDateString()}</span>
            )}
            {subscription.next_send_at && (
              <span>Next: {new Date(subscription.next_send_at).toLocaleDateString()}</span>
            )}
          </div>
        </div>
      </div>
      <Button
        variant="ghost"
        size="icon"
        onClick={handleDelete}
        disabled={deleteMutation.isPending}
        className="text-muted-foreground hover:text-destructive"
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </div>
  );
}

// ---------- Create Subscription Dialog ----------

function CreateSubscriptionDialog({ onClose }: { onClose: () => void }) {
  const createMutation = useCreateSubscription();
  const [reportType, setReportType] = React.useState('');
  const [frequency, setFrequency] = React.useState<CreateSubscriptionInput['frequency']>('weekly');
  const [deliveryMethod, setDeliveryMethod] =
    React.useState<CreateSubscriptionInput['delivery_method']>('email');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportType) return;

    createMutation.mutate(
      {
        report_type: reportType,
        frequency,
        delivery_method: deliveryMethod,
      },
      {
        onSuccess: () => {
          onClose();
          setReportType('');
          setFrequency('weekly');
          setDeliveryMethod('email');
        },
      }
    );
  };

  return (
    <DialogContent>
      <form onSubmit={handleSubmit}>
        <DialogHeader>
          <DialogTitle>Create Report Subscription</DialogTitle>
          <DialogDescription>
            Set up automatic report generation and delivery on a recurring schedule.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="report-type">Report Type</Label>
            <Select value={reportType} onValueChange={setReportType}>
              <SelectTrigger id="report-type">
                <SelectValue placeholder="Select report type..." />
              </SelectTrigger>
              <SelectContent>
                {REPORT_TYPES.map((rt) => (
                  <SelectItem key={rt.value} value={rt.value}>
                    {rt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="frequency">Frequency</Label>
            <Select
              value={frequency}
              onValueChange={(val) =>
                setFrequency(val as CreateSubscriptionInput['frequency'])
              }
            >
              <SelectTrigger id="frequency">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FREQUENCIES.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="delivery-method">Delivery Method</Label>
            <Select
              value={deliveryMethod}
              onValueChange={(val) =>
                setDeliveryMethod(val as CreateSubscriptionInput['delivery_method'])
              }
            >
              <SelectTrigger id="delivery-method">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {DELIVERY_METHODS.map((dm) => (
                  <SelectItem key={dm.value} value={dm.value}>
                    <span className="flex items-center gap-2">
                      <dm.icon className="h-3.5 w-3.5" />
                      {dm.label}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={!reportType || createMutation.isPending}>
            {createMutation.isPending ? 'Creating...' : 'Create Subscription'}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

// ---------- Skeleton ----------

function ReportSubscriptionsSkeleton() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <Skeleton className="h-5 w-40 mb-2" />
            <Skeleton className="h-4 w-64" />
          </div>
          <Skeleton className="h-9 w-36" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full rounded-lg" />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
