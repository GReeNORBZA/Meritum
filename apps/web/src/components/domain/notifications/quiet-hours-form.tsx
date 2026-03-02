'use client';

import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type { QuietHoursConfig } from '@/hooks/api/use-notifications';

// ---------- Constants ----------

const COMMON_TIMEZONES = [
  { value: 'America/Edmonton', label: 'Mountain Time (Edmonton)' },
  { value: 'America/Vancouver', label: 'Pacific Time (Vancouver)' },
  { value: 'America/Winnipeg', label: 'Central Time (Winnipeg)' },
  { value: 'America/Toronto', label: 'Eastern Time (Toronto)' },
  { value: 'America/Halifax', label: 'Atlantic Time (Halifax)' },
  { value: 'America/St_Johns', label: 'Newfoundland Time (St. John\'s)' },
  { value: 'UTC', label: 'UTC' },
];

// ---------- Types ----------

interface QuietHoursFormProps {
  value: QuietHoursConfig;
  onChange: (updated: QuietHoursConfig) => void;
  disabled?: boolean;
}

// ---------- Component ----------

function QuietHoursForm({ value, onChange, disabled }: QuietHoursFormProps) {
  const handleEnabledChange = (checked: boolean) => {
    onChange({ ...value, enabled: checked });
  };

  const handleStartTimeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, start_time: e.target.value });
  };

  const handleEndTimeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, end_time: e.target.value });
  };

  const handleTimezoneChange = (timezone: string) => {
    onChange({ ...value, timezone });
  };

  return (
    <div className="space-y-4">
      {/* Enable/Disable */}
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label htmlFor="quiet-hours-toggle" className="text-sm font-medium">
            Enable Quiet Hours
          </Label>
          <p className="text-xs text-muted-foreground">
            Pause notifications during specified hours
          </p>
        </div>
        <Switch
          id="quiet-hours-toggle"
          checked={value.enabled}
          onCheckedChange={handleEnabledChange}
          disabled={disabled}
        />
      </div>

      {value.enabled && (
        <>
          {/* Time Range */}
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="quiet-start-time" className="text-sm">
                Start Time
              </Label>
              <Input
                id="quiet-start-time"
                type="time"
                value={value.start_time}
                onChange={handleStartTimeChange}
                disabled={disabled}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="quiet-end-time" className="text-sm">
                End Time
              </Label>
              <Input
                id="quiet-end-time"
                type="time"
                value={value.end_time}
                onChange={handleEndTimeChange}
                disabled={disabled}
              />
            </div>
          </div>

          {/* Timezone */}
          <div className="space-y-2">
            <Label htmlFor="quiet-timezone" className="text-sm">
              Timezone
            </Label>
            <Select
              value={value.timezone}
              onValueChange={handleTimezoneChange}
              disabled={disabled}
            >
              <SelectTrigger id="quiet-timezone">
                <SelectValue placeholder="Select timezone" />
              </SelectTrigger>
              <SelectContent>
                {COMMON_TIMEZONES.map((tz) => (
                  <SelectItem key={tz.value} value={tz.value}>
                    {tz.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </>
      )}
    </div>
  );
}

export { QuietHoursForm, COMMON_TIMEZONES };
export type { QuietHoursFormProps };
