'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useShiftSchedule } from '@/hooks/api/use-mobile';
import { ChevronLeft, ChevronRight, Loader2, CalendarDays } from 'lucide-react';
import { cn } from '@/lib/utils';

const WEEKDAY_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTH_NAMES = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
];

function getMonthString(year: number, month: number): string {
  return `${year}-${String(month + 1).padStart(2, '0')}`;
}

function getDaysInMonth(year: number, month: number): number {
  return new Date(year, month + 1, 0).getDate();
}

function getFirstDayOfWeek(year: number, month: number): number {
  return new Date(year, month, 1).getDay();
}

export default function MobileSchedulePage() {
  const today = new Date();
  const [currentYear, setCurrentYear] = useState(today.getFullYear());
  const [currentMonth, setCurrentMonth] = useState(today.getMonth());
  const [selectedDate, setSelectedDate] = useState<string | null>(null);

  const monthString = getMonthString(currentYear, currentMonth);
  const { data, isLoading } = useShiftSchedule(monthString);
  const scheduleEntries = data?.data ?? [];

  // Map dates to entries for quick lookup
  const dateMap = useMemo(() => {
    const map = new Map<string, typeof scheduleEntries>();
    for (const entry of scheduleEntries) {
      const dateKey = entry.date.split('T')[0];
      const existing = map.get(dateKey) ?? [];
      existing.push(entry);
      map.set(dateKey, existing);
    }
    return map;
  }, [scheduleEntries]);

  const daysInMonth = getDaysInMonth(currentYear, currentMonth);
  const firstDayOfWeek = getFirstDayOfWeek(currentYear, currentMonth);

  const todayStr = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;

  const handlePrevMonth = () => {
    if (currentMonth === 0) {
      setCurrentYear((y) => y - 1);
      setCurrentMonth(11);
    } else {
      setCurrentMonth((m) => m - 1);
    }
    setSelectedDate(null);
  };

  const handleNextMonth = () => {
    if (currentMonth === 11) {
      setCurrentYear((y) => y + 1);
      setCurrentMonth(0);
    } else {
      setCurrentMonth((m) => m + 1);
    }
    setSelectedDate(null);
  };

  // Build calendar grid cells
  const calendarCells: (number | null)[] = [];
  for (let i = 0; i < firstDayOfWeek; i++) {
    calendarCells.push(null);
  }
  for (let d = 1; d <= daysInMonth; d++) {
    calendarCells.push(d);
  }

  const selectedEntries = selectedDate ? (dateMap.get(selectedDate) ?? []) : [];

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold">Shift Schedule</h1>

      <Card>
        <CardHeader className="pb-2">
          {/* Month Navigation */}
          <div className="flex items-center justify-between">
            <Button variant="ghost" size="icon" onClick={handlePrevMonth}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <CardTitle className="text-base">
              {MONTH_NAMES[currentMonth]} {currentYear}
            </CardTitle>
            <Button variant="ghost" size="icon" onClick={handleNextMonth}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <>
              {/* Weekday Headers */}
              <div className="grid grid-cols-7 mb-1">
                {WEEKDAY_LABELS.map((label) => (
                  <div
                    key={label}
                    className="text-center text-xs font-medium text-muted-foreground py-1"
                  >
                    {label}
                  </div>
                ))}
              </div>

              {/* Calendar Grid */}
              <div className="grid grid-cols-7 gap-px">
                {calendarCells.map((day, idx) => {
                  if (day === null) {
                    return <div key={`empty-${idx}`} className="h-10" />;
                  }

                  const dateStr = `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
                  const hasShifts = dateMap.has(dateStr);
                  const isToday = dateStr === todayStr;
                  const isSelected = dateStr === selectedDate;

                  return (
                    <button
                      key={dateStr}
                      type="button"
                      onClick={() => setSelectedDate(isSelected ? null : dateStr)}
                      className={cn(
                        'relative flex flex-col items-center justify-center h-10 rounded-md text-sm transition-colors',
                        isToday && 'font-bold',
                        isSelected
                          ? 'bg-primary text-primary-foreground'
                          : 'hover:bg-muted',
                        !isSelected && isToday && 'ring-1 ring-primary'
                      )}
                    >
                      {day}
                      {hasShifts && !isSelected && (
                        <span className="absolute bottom-1 h-1 w-1 rounded-full bg-primary" />
                      )}
                      {hasShifts && isSelected && (
                        <span className="absolute bottom-1 h-1 w-1 rounded-full bg-primary-foreground" />
                      )}
                    </button>
                  );
                })}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Selected Date Shifts */}
      {selectedDate && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              Shifts on {new Date(selectedDate + 'T00:00:00').toLocaleDateString(undefined, {
                weekday: 'long',
                month: 'long',
                day: 'numeric',
              })}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {selectedEntries.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">
                No shifts scheduled
              </p>
            ) : (
              <ul className="divide-y">
                {selectedEntries.map((entry) => (
                  <li key={entry.id} className="flex items-center gap-3 py-3">
                    <CalendarDays className="h-4 w-4 text-muted-foreground" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">
                        {entry.start_time} &ndash; {entry.end_time}
                      </p>
                      {entry.location_name && (
                        <p className="text-xs text-muted-foreground truncate">
                          {entry.location_name}
                        </p>
                      )}
                      {entry.shift_type && (
                        <span className="inline-block mt-1 text-xs bg-muted rounded px-1.5 py-0.5">
                          {entry.shift_type}
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
