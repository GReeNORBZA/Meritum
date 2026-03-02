'use client';

import * as React from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useClaim, type Claim } from '@/hooks/api/use-claims';
import { ROUTES } from '@/config/routes';
import { StatusBadge } from '@/components/shared/status-badge';
import { ClaimStateActions } from '@/components/domain/claims/claim-state-actions';
import { RejectionDetail } from '@/components/domain/claims/rejection-detail';
import { ResubmitForm } from '@/components/domain/claims/resubmit-form';
import { WriteOffDialog } from '@/components/domain/claims/write-off-dialog';
import { FeeBreakdown } from '@/components/domain/claims/fee-breakdown';
import { JustificationForm } from '@/components/domain/claims/justification-form';
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
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Clock,
  Brain,
  History,
} from 'lucide-react';

// ---------- Loading Skeleton ----------

function ClaimDetailSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-8 w-64" />
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        <div className="space-y-6">
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

function ValidationResults({ results }: { results: Claim['validation_results'] }) {
  if (!results || results.length === 0) return null;

  const errors = results.filter((r) => r.severity === 'ERROR' && !r.passed);
  const warnings = results.filter((r) => r.severity === 'WARNING' && !r.passed);
  const passed = results.filter((r) => r.passed);

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
            {errors.map((r) => (
              <div
                key={r.check_id}
                className="flex items-start gap-2 text-sm text-destructive"
              >
                <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{r.message}</span>
              </div>
            ))}
          </div>
        )}
        {warnings.length > 0 && (
          <div className="space-y-1">
            {warnings.map((r) => (
              <div
                key={r.check_id}
                className="flex items-start gap-2 text-sm text-yellow-700 dark:text-yellow-400"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{r.message}</span>
              </div>
            ))}
          </div>
        )}
        {passed.length > 0 && (
          <div className="space-y-1">
            {passed.map((r) => (
              <div
                key={r.check_id}
                className="flex items-start gap-2 text-sm text-green-700 dark:text-green-400"
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

// ---------- Audit Trail ----------

function AuditTrail({ entries }: { entries: Claim['audit_trail'] }) {
  if (!entries || entries.length === 0) return null;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <History className="h-4 w-4" />
          Audit Trail
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {entries.map((entry) => (
            <div key={entry.id} className="flex items-start gap-3 text-sm">
              <Clock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">
                    {entry.action.replace('claim.', '').replace(/_/g, ' ')}
                  </span>
                  <Badge variant="outline" className="text-xs">
                    {entry.actor_type}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  {entry.actor_name} - {formatRelative(entry.created_at)}
                </p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- Flags Section ----------

function ClaimFlags({ flags }: { flags: Claim['flags'] }) {
  if (!flags || flags.length === 0) return null;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <AlertTriangle className="h-4 w-4" />
          Flags & Warnings
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {flags.map((flag) => (
          <div
            key={flag.id}
            className={`flex items-start gap-2 rounded-md p-2 text-sm ${
              flag.severity === 'ERROR'
                ? 'bg-destructive/10 text-destructive'
                : flag.severity === 'WARNING'
                  ? 'bg-yellow-50 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200'
                  : 'bg-blue-50 text-blue-800 dark:bg-blue-950 dark:text-blue-200'
            }`}
          >
            {flag.severity === 'ERROR' ? (
              <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
            ) : flag.severity === 'WARNING' ? (
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            ) : (
              <Info className="mt-0.5 h-4 w-4 shrink-0" />
            )}
            <div>
              <span>{flag.message}</span>
              {flag.resolved && (
                <Badge variant="secondary" className="ml-2 text-xs">
                  Resolved
                </Badge>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

// ---------- Main Page ----------

export default function ClaimDetailPage() {
  const params = useParams();
  const router = useRouter();
  const claimId = params.id as string;

  const { data, isLoading } = useClaim(claimId);
  const claim = data?.data;

  const [showWriteOff, setShowWriteOff] = React.useState(false);
  const [showResubmit, setShowResubmit] = React.useState(false);
  const [showJustification, setShowJustification] = React.useState(false);

  if (isLoading) {
    return <ClaimDetailSkeleton />;
  }

  if (!claim) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-lg text-muted-foreground">Claim not found.</p>
        <Link href={ROUTES.CLAIMS}>
          <Button variant="outline" className="mt-4">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Claims
          </Button>
        </Link>
      </div>
    );
  }

  const feeData =
    claim.line_items.length > 0
      ? {
          line_items: claim.line_items.map((li) => ({
            health_service_code: li.health_service_code,
            base_fee: li.fee_amount,
            modifier_adjustments: li.modifiers.map((m) => ({
              modifier: m,
              adjustment: '0.00',
            })),
            calculated_fee: li.fee_amount,
          })),
          total_fee: claim.total_fee,
        }
      : null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4">
          <Link href={ROUTES.CLAIMS}>
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight font-mono">
                {claim.claim_number}
              </h1>
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
          {claim.state === 'REJECTED' && (
            <Button
              variant="outline"
              onClick={() => setShowResubmit(!showResubmit)}
            >
              <FileText className="mr-2 h-4 w-4" />
              {showResubmit ? 'Hide Resubmit Form' : 'Edit & Resubmit'}
            </Button>
          )}
          <Button
            variant="outline"
            onClick={() => setShowJustification(!showJustification)}
          >
            <FileText className="mr-2 h-4 w-4" />
            Add Justification
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        {/* Main Content */}
        <div className="space-y-6">
          {/* Rejection Detail */}
          <RejectionDetail claim={claim} />

          {/* Resubmit Form */}
          {showResubmit && claim.state === 'REJECTED' && (
            <ResubmitForm
              claim={claim}
              onSuccess={() => {
                setShowResubmit(false);
                router.refresh();
              }}
            />
          )}

          {/* Justification Form */}
          {showJustification && (
            <JustificationForm
              claimId={claim.id}
              onSuccess={() => setShowJustification(false)}
            />
          )}

          {/* Claim Details Card */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Claim Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase text-muted-foreground">
                    Patient
                  </p>
                  <p className="text-sm font-medium">
                    {claim.patient_name || claim.patient_id}
                  </p>
                  {claim.patient_phn && (
                    <p className="text-xs text-muted-foreground font-mono">
                      PHN: {claim.patient_phn}
                    </p>
                  )}
                </div>

                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase text-muted-foreground">
                    Date of Service
                  </p>
                  <p className="text-sm">{formatDate(claim.date_of_service)}</p>
                </div>

                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase text-muted-foreground">
                    Encounter Type
                  </p>
                  <p className="text-sm capitalize">
                    {claim.encounter_type || 'Not specified'}
                  </p>
                </div>

                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase text-muted-foreground">
                    Functional Centre
                  </p>
                  <p className="text-sm">{claim.functional_centre || 'Not specified'}</p>
                </div>

                {claim.referring_provider_name && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium uppercase text-muted-foreground">
                      Referring Physician
                    </p>
                    <p className="text-sm">{claim.referring_provider_name}</p>
                  </div>
                )}

                {claim.time_spent != null && claim.time_spent > 0 && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium uppercase text-muted-foreground">
                      Time Spent
                    </p>
                    <p className="text-sm">{claim.time_spent} minutes</p>
                  </div>
                )}

                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase text-muted-foreground">
                    Import Source
                  </p>
                  <Badge variant="outline">{claim.import_source}</Badge>
                </div>

                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase text-muted-foreground">
                    Clean Claim
                  </p>
                  <Badge variant={claim.is_clean ? 'success' : 'warning'}>
                    {claim.is_clean ? 'Yes' : 'No'}
                  </Badge>
                </div>
              </div>

              <Separator className="my-4" />

              {/* Line Items */}
              <div className="space-y-3">
                <p className="text-sm font-medium">Line Items</p>
                {claim.line_items.map((item, index) => (
                  <div
                    key={item.id || index}
                    className="flex items-center justify-between rounded-md border p-3"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium">
                          {item.health_service_code}
                        </span>
                        {item.hsc_description && (
                          <span className="text-sm text-muted-foreground">
                            {item.hsc_description}
                          </span>
                        )}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {item.modifiers.map((mod) => (
                          <Badge key={mod} variant="outline" className="text-xs font-mono">
                            {mod}
                          </Badge>
                        ))}
                        {item.diagnostic_codes.map((code) => (
                          <Badge key={code} variant="secondary" className="text-xs font-mono">
                            DX: {code}
                          </Badge>
                        ))}
                        {item.calls > 1 && (
                          <Badge variant="secondary" className="text-xs">
                            x{item.calls} calls
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium">{formatCurrency(item.fee_amount)}</p>
                      {item.assessed_amount && (
                        <p className="text-xs text-muted-foreground">
                          Assessed: {formatCurrency(item.assessed_amount)}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Validation Results */}
          <ValidationResults results={claim.validation_results} />

          {/* Flags */}
          <ClaimFlags flags={claim.flags} />

          {/* Audit Trail */}
          <AuditTrail entries={claim.audit_trail} />
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Actions */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <ClaimStateActions
                claim={claim}
                onWriteOff={() => setShowWriteOff(true)}
              />
            </CardContent>
          </Card>

          {/* Fee Summary */}
          <FeeBreakdown feeData={feeData} />

          {/* Total Amounts */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Amounts</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Billed</span>
                <span className="font-medium">{formatCurrency(claim.total_fee)}</span>
              </div>
              {claim.total_assessed && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Assessed</span>
                  <span className="font-medium">
                    {formatCurrency(claim.total_assessed)}
                  </span>
                </div>
              )}
              {claim.batch_id && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Batch</span>
                  <Link
                    href={ROUTES.BATCH_DETAIL(claim.batch_id)}
                    className="font-mono text-primary hover:underline"
                  >
                    View Batch
                  </Link>
                </div>
              )}
            </CardContent>
          </Card>

          {/* AI Suggestions Placeholder */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Brain className="h-4 w-4" />
                AI Suggestions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                AI-powered coding suggestions will appear here when available.
                The system analyzes your claim for potential optimizations and
                common billing patterns.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Write-off Dialog */}
      <WriteOffDialog
        claimId={claim.id}
        open={showWriteOff}
        onOpenChange={setShowWriteOff}
        onComplete={() => router.refresh()}
      />
    </div>
  );
}
