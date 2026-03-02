'use client';

import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Copy, Check, Gift, Users, DollarSign } from 'lucide-react';

interface ReferralData {
  referral_code: string;
  referral_url: string;
  total_referrals: number;
  successful_referrals: number;
  credits_earned: number;
}

export default function ReferralPage() {
  const [copied, setCopied] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: queryKeys.subscription.referral(),
    queryFn: () => api.get<{ data: ReferralData }>('/api/v1/subscription/referral'),
  });

  const referral = data?.data;

  const copyCode = async () => {
    if (!referral) return;
    await navigator.clipboard.writeText(referral.referral_url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Referral Program</h1>
        <p className="text-muted-foreground">Invite colleagues and earn billing credits</p>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-32" />
          <Skeleton className="h-24" />
        </div>
      ) : referral ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Gift className="h-5 w-5" />
                Your Referral Link
              </CardTitle>
              <CardDescription>
                Share this link with colleagues to earn credits for each successful sign-up
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-2">
                <div className="flex-1 rounded-md border bg-muted/50 px-3 py-2">
                  <p className="text-sm font-mono truncate">{referral.referral_url}</p>
                </div>
                <Button variant="outline" size="sm" onClick={copyCode}>
                  {copied ? (
                    <Check className="h-4 w-4 text-success" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Referral code: <span className="font-mono font-medium">{referral.referral_code}</span>
              </p>
            </CardContent>
          </Card>

          <div className="grid gap-4 sm:grid-cols-3">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <Users className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <p className="text-2xl font-bold">{referral.total_referrals}</p>
                    <p className="text-xs text-muted-foreground">Total Referrals</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <Check className="h-5 w-5 text-success" />
                  <div>
                    <p className="text-2xl font-bold">{referral.successful_referrals}</p>
                    <p className="text-xs text-muted-foreground">Successful</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <DollarSign className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <p className="text-2xl font-bold">${referral.credits_earned}</p>
                    <p className="text-xs text-muted-foreground">Credits Earned</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </>
      ) : (
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-muted-foreground">Referral program information is not available.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
