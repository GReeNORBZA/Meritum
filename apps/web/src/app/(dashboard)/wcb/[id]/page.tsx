'use client';

import * as React from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useWcbClaim, useSubmitWcbClaim, type WcbClaim } from '@/hooks/api/use-wcb';
import { ROUTES } from '@/config/routes';
import { WcbFormBuilder } from '@/components/domain/wcb/wcb-form-builder';
import { TimingTierIndicator } from '@/components/domain/wcb/timing-tier-indicator';
import { StatusBadge } from '@/components/shared/status-badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { formatCurrency } from '@/lib/formatters/currency';
import { formatDate, formatDateTime, formatRelative } from '@/lib/formatters/date';
import {
  ArrowLeft,
  FileText,
  Edit,
  Send,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
} from 'lucide-react';

// ---------- Loading Skeleton ----------

function WcbDetailSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-8 w-64" />
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        <div className="space-y-6">
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-32 w-full" />
        </div>
      </div>
    </div>
  );
}

// ---------- Validation Results ----------

function ValidationResults({
  results,
}: {
  results: WcbClaim['validation_results'];
}) {
  if (!results || results.length === 0) return null;

  const errors = results.filter((r) => r.severity === 'ERROR');
  const warnings = results.filter((r) => r.severity === 'WARNING');
  const info = results.filter((r) => r.severity === 'INFO');

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <CheckCircle className="h-4 w-4" />
          Validation Results
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {errors.length > 0 && (
          <div className="space-y-1">
            {errors.map((r, i) => (
              <div
                key={`err-${i}`}
                className="flex items-start gap-2 text-sm text-destructive"
              >
                <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  {r.message}
                  {r.field && (
                    <span className="ml-1 font-mono text-xs">({r.field})</span>
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
        {warnings.length > 0 && (
          <div className="space-y-1">
            {warnings.map((r, i) => (
              <div
                key={`warn-${i}`}
                className="flex items-start gap-2 text-sm text-yellow-700 dark:text-yellow-400"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{r.message}</span>
              </div>
            ))}
          </div>
        )}
        {info.length > 0 && (
          <div className="space-y-1">
            {info.map((r, i) => (
              <div
                key={`info-${i}`}
                className="flex items-start gap-2 text-sm text-blue-700 dark:text-blue-400"
              >
                <CheckCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{r.message}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------- Main Page ----------

export default function WcbClaimDetailPage() {
  const params = useParams();
  const router = useRouter();
  const claimId = params.id as string;

  const { data, isLoading } = useWcbClaim(claimId);
  const submitMutation = useSubmitWcbClaim();
  const claim = data?.data;

  const [isEditing, setIsEditing] = React.useState(false);

  if (isLoading) {
    return <WcbDetailSkeleton />;
  }

  if (!claim) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-lg text-muted-foreground">WCB claim not found.</p>
        <Link href={ROUTES.WCB}>
          <Button variant="outline" className="mt-4">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to WCB Claims
          </Button>
        </Link>
      </div>
    );
  }

  const canEdit = claim.state === 'DRAFT' || claim.state === 'VALIDATED';
  const canSubmit = claim.state === 'DRAFT' || claim.state === 'VALIDATED';

  const handleSubmit = async () => {
    await submitMutation.mutateAsync(claimId);
  };

  // If editing, show the form builder
  if (isEditing && canEdit) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsEditing(false)}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight">
                Edit WCB Claim
              </h1>
              <Badge variant="outline" className="font-mono">
                {claim.form_id}
              </Badge>
              <StatusBadge status={claim.state} />
            </div>
            <p className="text-sm text-muted-foreground">
              {claim.wcb_claim_number || claim.id.slice(0, 8)}
            </p>
          </div>
        </div>

        <WcbFormBuilder
          formType={claim.form_id}
          claimId={claimId}
          initialValues={claim as unknown as Record<string, unknown>}
        />
      </div>
    );
  }

  // Read-only detail view
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4">
          <Link href={ROUTES.WCB}>
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight font-mono">
                {claim.wcb_claim_number || claim.id.slice(0, 8)}
              </h1>
              <Badge variant="outline" className="font-mono">
                {claim.form_id}
              </Badge>
              <StatusBadge status={claim.state} />
            </div>
            <p className="text-sm text-muted-foreground">
              Created {formatRelative(claim.created_at)}
              {claim.submitted_at &&
                ` | Submitted ${formatDateTime(claim.submitted_at)}`}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          {canEdit && (
            <Button variant="outline" onClick={() => setIsEditing(true)}>
              <Edit className="mr-2 h-4 w-4" />
              Edit
            </Button>
          )}
          {canSubmit && (
            <Button
              onClick={handleSubmit}
              disabled={submitMutation.isPending}
            >
              {submitMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Send className="mr-2 h-4 w-4" />
              )}
              Submit to WCB
            </Button>
          )}
        </div>
      </div>

      {submitMutation.isError && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {submitMutation.error instanceof Error
            ? submitMutation.error.message
            : 'Failed to submit claim. Please try again.'}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        {/* Main Content - Read Only Form */}
        <div className="space-y-6">
          <WcbFormBuilder
            formType={claim.form_id}
            claimId={claimId}
            initialValues={claim as unknown as Record<string, unknown>}
            readOnly
          />

          {/* Validation Results */}
          <ValidationResults results={claim.validation_results} />
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Claim Summary */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <FileText className="h-4 w-4" />
                Claim Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Form Type</span>
                <Badge variant="outline" className="font-mono text-xs">
                  {claim.form_id}
                </Badge>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Status</span>
                <StatusBadge status={claim.state} />
              </div>
              {claim.patient_name && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Patient</span>
                  <span className="font-medium">{claim.patient_name}</span>
                </div>
              )}
              {claim.date_of_injury && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Date of Injury</span>
                  <span>{formatDate(claim.date_of_injury)}</span>
                </div>
              )}
              {claim.total_fee && (
                <>
                  <Separator />
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Total Fee</span>
                    <span className="font-medium">
                      {formatCurrency(claim.total_fee)}
                    </span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Timing Tier */}
          <TimingTierIndicator
            timingTier={claim.timing_tier}
            deadlineInfo={claim.deadline_info}
          />

          {/* Dates */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Important Dates</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Created</span>
                <span>{formatDate(claim.created_at)}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Updated</span>
                <span>{formatRelative(claim.updated_at)}</span>
              </div>
              {claim.submitted_at && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Submitted</span>
                  <span>{formatDateTime(claim.submitted_at)}</span>
                </div>
              )}
              {claim.date_of_examination && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Examination</span>
                  <span>{formatDate(claim.date_of_examination)}</span>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
