'use client';

import { useLearningState, useUnsuppressRule } from '@/hooks/api/use-intelligence';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Brain, TrendingUp, CheckCircle, XCircle, Loader2, RotateCcw } from 'lucide-react';

// ---------- Component ----------

function LearningStateSummary() {
  const { data, isLoading, isError } = useLearningState();
  const unsuppressRule = useUnsuppressRule();

  const learningState = data?.data;

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            Learning State
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-20 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (isError || !learningState) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            Learning State
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Unable to load learning state. Please try again later.
          </p>
        </CardContent>
      </Card>
    );
  }

  const acceptancePercent = Math.round(learningState.acceptance_rate * 100);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Brain className="h-5 w-5" />
          Learning State
        </CardTitle>
        <CardDescription>
          How the AI coach has adapted to your preferences
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Stats Grid */}
        <div className="grid gap-4 sm:grid-cols-3">
          <div className="rounded-lg border p-4 text-center">
            <TrendingUp className="mx-auto h-5 w-5 text-muted-foreground" />
            <p className="mt-2 text-2xl font-bold">{learningState.total_suggestions}</p>
            <p className="text-xs text-muted-foreground">Total Suggestions</p>
          </div>
          <div className="rounded-lg border p-4 text-center">
            <CheckCircle className="mx-auto h-5 w-5 text-green-600" />
            <p className="mt-2 text-2xl font-bold">{learningState.accepted_count}</p>
            <p className="text-xs text-muted-foreground">Accepted</p>
          </div>
          <div className="rounded-lg border p-4 text-center">
            <XCircle className="mx-auto h-5 w-5 text-gray-400" />
            <p className="mt-2 text-2xl font-bold">{learningState.dismissed_count}</p>
            <p className="text-xs text-muted-foreground">Dismissed</p>
          </div>
        </div>

        {/* Acceptance Rate */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="font-medium">Acceptance Rate</span>
            <span className="text-muted-foreground">{acceptancePercent}%</span>
          </div>
          <Progress value={acceptancePercent} />
        </div>

        {/* Suppressed Rules */}
        {learningState.suppressed_rules.length > 0 && (
          <>
            <Separator />
            <div className="space-y-3">
              <h4 className="text-sm font-semibold">Suppressed Rules</h4>
              <p className="text-xs text-muted-foreground">
                These rules have been suppressed based on your feedback. Unsuppress to start
                receiving suggestions from them again.
              </p>
              <div className="space-y-2">
                {learningState.suppressed_rules.map((rule) => (
                  <div
                    key={rule.rule_id}
                    className="flex items-center justify-between rounded-md border px-3 py-2"
                  >
                    <div>
                      <span className="text-sm font-medium">{rule.rule_name}</span>
                      <p className="text-xs text-muted-foreground">
                        Suppressed{' '}
                        {new Date(rule.suppressed_at).toLocaleDateString()}
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => unsuppressRule.mutate(rule.rule_id)}
                      disabled={unsuppressRule.isPending}
                    >
                      {unsuppressRule.isPending ? (
                        <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <RotateCcw className="mr-1.5 h-3.5 w-3.5" />
                      )}
                      Unsuppress
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {learningState.suppressed_rules.length === 0 && (
          <>
            <Separator />
            <div className="text-center">
              <Badge variant="outline">No suppressed rules</Badge>
              <p className="mt-1 text-xs text-muted-foreground">
                All suggestion rules are currently active
              </p>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export { LearningStateSummary };
