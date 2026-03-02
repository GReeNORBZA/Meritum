'use client';

import { ClaimForm } from '@/components/domain/claims/claim-form';

export default function NewClaimPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">New AHCIP Claim</h1>
        <p className="text-muted-foreground">
          Create a new claim for submission to Alberta Health Care Insurance Plan
        </p>
      </div>

      {/* Claim Form */}
      <ClaimForm />
    </div>
  );
}
