'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle } from 'lucide-react';
import type { Claim } from '@/hooks/api/use-claims';

// ---------- Types ----------

interface RejectionDetailProps {
  claim: Claim;
}

// ---------- Component ----------

function RejectionDetail({ claim }: RejectionDetailProps) {
  if (claim.state !== 'REJECTED' || !claim.rejection_reason) {
    return null;
  }

  return (
    <Card className="border-destructive/50">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base text-destructive">
          <AlertTriangle className="h-4 w-4" />
          Rejection Details
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {claim.rejection_code && (
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-muted-foreground">
              Code:
            </span>
            <Badge variant="destructive" className="font-mono">
              {claim.rejection_code}
            </Badge>
          </div>
        )}

        <div>
          <span className="text-sm font-medium text-muted-foreground">
            Reason:
          </span>
          <p className="mt-1 text-sm">{claim.rejection_reason}</p>
        </div>

        {claim.rejection_details && (
          <div>
            <span className="text-sm font-medium text-muted-foreground">
              Additional Details:
            </span>
            <p className="mt-1 text-sm text-muted-foreground">
              {claim.rejection_details}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export { RejectionDetail };
export type { RejectionDetailProps };
