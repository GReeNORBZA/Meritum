'use client';

import { useEffect, useState } from 'react';
import {
  useIntelligencePreferences,
  useUpdateIntelligencePreferences,
  useUnsuppressRule,
  type AggressivenessLevel,
} from '@/hooks/api/use-intelligence';
import { LearningStateSummary } from '@/components/domain/intelligence/learning-state';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2, Sparkles, RotateCcw } from 'lucide-react';

// ---------- Component ----------

export default function AICoachPage() {
  const { data, isLoading } = useIntelligencePreferences();
  const updatePreferences = useUpdateIntelligencePreferences();
  const unsuppressRule = useUnsuppressRule();

  const preferences = data?.data;

  const [suggestionsEnabled, setSuggestionsEnabled] = useState(false);
  const [aggressiveness, setAggressiveness] = useState<AggressivenessLevel>('balanced');
  const [autoApplyTierA, setAutoApplyTierA] = useState(false);

  // Sync state when data loads
  useEffect(() => {
    if (preferences) {
      setSuggestionsEnabled(preferences.suggestions_enabled);
      setAggressiveness(preferences.aggressiveness);
      setAutoApplyTierA(preferences.auto_apply_tier_a);
    }
  }, [preferences]);

  const handleToggleSuggestions = (checked: boolean) => {
    setSuggestionsEnabled(checked);
    updatePreferences.mutate({ suggestions_enabled: checked });
  };

  const handleAggressivenessChange = (value: string) => {
    const level = value as AggressivenessLevel;
    setAggressiveness(level);
    updatePreferences.mutate({ aggressiveness: level });
  };

  const handleAutoApplyChange = (checked: boolean) => {
    setAutoApplyTierA(checked);
    updatePreferences.mutate({ auto_apply_tier_a: checked });
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">AI Coach</h2>
          <p className="text-muted-foreground">
            Configure your AI-powered billing assistant
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

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">AI Coach</h2>
        <p className="text-muted-foreground">
          Configure your AI-powered billing assistant
        </p>
      </div>

      {/* Preferences Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5" />
            Suggestion Preferences
          </CardTitle>
          <CardDescription>
            Control how the AI coach provides billing suggestions
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Toggle AI Suggestions */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="suggestions-toggle" className="text-sm font-medium">
                Enable AI Suggestions
              </Label>
              <p className="text-xs text-muted-foreground">
                Receive AI-powered suggestions to optimize your claims
              </p>
            </div>
            <Switch
              id="suggestions-toggle"
              checked={suggestionsEnabled}
              onCheckedChange={handleToggleSuggestions}
              disabled={updatePreferences.isPending}
            />
          </div>

          <Separator />

          {/* Aggressiveness Level */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="aggressiveness-select" className="text-sm font-medium">
                Suggestion Aggressiveness
              </Label>
              <p className="text-xs text-muted-foreground">
                Controls how frequently and broadly the AI suggests changes
              </p>
            </div>
            <Select
              value={aggressiveness}
              onValueChange={handleAggressivenessChange}
              disabled={!suggestionsEnabled || updatePreferences.isPending}
            >
              <SelectTrigger id="aggressiveness-select" className="w-[180px]">
                <SelectValue placeholder="Select level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="conservative">Conservative</SelectItem>
                <SelectItem value="balanced">Balanced</SelectItem>
                <SelectItem value="aggressive">Aggressive</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Separator />

          {/* Auto-apply Tier A */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="auto-apply-toggle" className="text-sm font-medium">
                Auto-apply Tier A Suggestions
              </Label>
              <p className="text-xs text-muted-foreground">
                Automatically apply high-confidence suggestions without manual review
              </p>
            </div>
            <Switch
              id="auto-apply-toggle"
              checked={autoApplyTierA}
              onCheckedChange={handleAutoApplyChange}
              disabled={!suggestionsEnabled || updatePreferences.isPending}
            />
          </div>

          {updatePreferences.isPending && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Saving preferences...
            </div>
          )}
        </CardContent>
      </Card>

      {/* Suppressed Rules Card */}
      {preferences && preferences.suppressed_rules.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Suppressed Rules</CardTitle>
            <CardDescription>
              Rules that have been suppressed based on your feedback. Unsuppress a rule to
              start receiving its suggestions again.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {preferences.suppressed_rules.map((rule) => (
                <div
                  key={rule.rule_id}
                  className="flex items-center justify-between rounded-md border px-3 py-2"
                >
                  <div>
                    <span className="text-sm font-medium">{rule.rule_name}</span>
                    <p className="text-xs text-muted-foreground">
                      Suppressed {new Date(rule.suppressed_at).toLocaleDateString()}
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
          </CardContent>
        </Card>
      )}

      {/* Learning State */}
      <LearningStateSummary />
    </div>
  );
}
