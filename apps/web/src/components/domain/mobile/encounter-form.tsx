'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BarcodeScanner } from '@/components/domain/mobile/barcode-scanner';
import { useLogEncounter } from '@/hooks/api/use-mobile';
import { ScanBarcode, Search, PenLine, Hash, Loader2, CheckCircle2 } from 'lucide-react';
import { cn } from '@/lib/utils';

type EntryMethod = 'barcode' | 'phn' | 'manual' | 'last4';

interface EncounterFormProps {
  shiftId: string;
  onLogged?: () => void;
}

export function EncounterForm({ shiftId, onLogged }: EncounterFormProps) {
  const [activeMethod, setActiveMethod] = useState<EntryMethod | null>(null);
  const [phnValue, setPhnValue] = useState('');
  const [manualPatientId, setManualPatientId] = useState('');
  const [last4Value, setLast4Value] = useState('');
  const [encounterType, setEncounterType] = useState('');
  const [success, setSuccess] = useState(false);

  const logEncounter = useLogEncounter();

  const resetForm = () => {
    setActiveMethod(null);
    setPhnValue('');
    setManualPatientId('');
    setLast4Value('');
    setEncounterType('');
  };

  const handleLog = (data: {
    patient_phn?: string;
    patient_id?: string;
    barcode_value?: string;
    last_four?: string;
  }) => {
    logEncounter.mutate(
      {
        shiftId,
        data: {
          ...data,
          encounter_type: encounterType || undefined,
        },
      },
      {
        onSuccess: () => {
          setSuccess(true);
          setTimeout(() => {
            setSuccess(false);
            resetForm();
            onLogged?.();
          }, 1500);
        },
      }
    );
  };

  // Success feedback
  if (success) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-2 py-8">
          <CheckCircle2 className="h-10 w-10 text-green-500" />
          <p className="text-sm font-medium text-green-700">Encounter logged</p>
        </CardContent>
      </Card>
    );
  }

  // Barcode scanner active
  if (activeMethod === 'barcode') {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Scan Patient Barcode</CardTitle>
        </CardHeader>
        <CardContent>
          <BarcodeScanner
            onScan={(value) => handleLog({ barcode_value: value })}
            onCancel={() => setActiveMethod(null)}
          />
        </CardContent>
      </Card>
    );
  }

  // Method selection + active form
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Log Encounter</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Method selection buttons */}
        {!activeMethod && (
          <div className="grid grid-cols-2 gap-2">
            <Button
              variant="outline"
              className="flex flex-col items-center gap-1 h-auto py-3"
              onClick={() => setActiveMethod('barcode')}
            >
              <ScanBarcode className="h-5 w-5" />
              <span className="text-xs">Barcode Scan</span>
            </Button>
            <Button
              variant="outline"
              className="flex flex-col items-center gap-1 h-auto py-3"
              onClick={() => setActiveMethod('phn')}
            >
              <Search className="h-5 w-5" />
              <span className="text-xs">PHN Search</span>
            </Button>
            <Button
              variant="outline"
              className="flex flex-col items-center gap-1 h-auto py-3"
              onClick={() => setActiveMethod('manual')}
            >
              <PenLine className="h-5 w-5" />
              <span className="text-xs">Manual Entry</span>
            </Button>
            <Button
              variant="outline"
              className="flex flex-col items-center gap-1 h-auto py-3"
              onClick={() => setActiveMethod('last4')}
            >
              <Hash className="h-5 w-5" />
              <span className="text-xs">Last 4 Digits</span>
            </Button>
          </div>
        )}

        {/* PHN Search Form */}
        {activeMethod === 'phn' && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (phnValue.trim()) {
                handleLog({ patient_phn: phnValue.trim() });
              }
            }}
            className="space-y-3"
          >
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Personal Health Number (PHN)
              </label>
              <input
                type="text"
                value={phnValue}
                onChange={(e) => setPhnValue(e.target.value)}
                placeholder="Enter PHN..."
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm"
                autoFocus
                inputMode="numeric"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Encounter Type (optional)
              </label>
              <select
                value={encounterType}
                onChange={(e) => setEncounterType(e.target.value)}
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-background"
              >
                <option value="">Select type...</option>
                <option value="CONSULT">Consult</option>
                <option value="FOLLOW_UP">Follow-up</option>
                <option value="PROCEDURE">Procedure</option>
                <option value="ASSESSMENT">Assessment</option>
              </select>
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={resetForm}
                className="flex-1"
              >
                Back
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={!phnValue.trim() || logEncounter.isPending}
                className="flex-1"
              >
                {logEncounter.isPending && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
                Log
              </Button>
            </div>
          </form>
        )}

        {/* Manual Entry Form */}
        {activeMethod === 'manual' && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (manualPatientId.trim()) {
                handleLog({ patient_id: manualPatientId.trim() });
              }
            }}
            className="space-y-3"
          >
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Patient ID
              </label>
              <input
                type="text"
                value={manualPatientId}
                onChange={(e) => setManualPatientId(e.target.value)}
                placeholder="Enter patient ID..."
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm"
                autoFocus
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Encounter Type (optional)
              </label>
              <select
                value={encounterType}
                onChange={(e) => setEncounterType(e.target.value)}
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-background"
              >
                <option value="">Select type...</option>
                <option value="CONSULT">Consult</option>
                <option value="FOLLOW_UP">Follow-up</option>
                <option value="PROCEDURE">Procedure</option>
                <option value="ASSESSMENT">Assessment</option>
              </select>
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={resetForm}
                className="flex-1"
              >
                Back
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={!manualPatientId.trim() || logEncounter.isPending}
                className="flex-1"
              >
                {logEncounter.isPending && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
                Log
              </Button>
            </div>
          </form>
        )}

        {/* Last 4 Digits Quick Entry */}
        {activeMethod === 'last4' && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (last4Value.length === 4) {
                handleLog({ last_four: last4Value });
              }
            }}
            className="space-y-3"
          >
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Last 4 Digits of PHN
              </label>
              <input
                type="text"
                value={last4Value}
                onChange={(e) => {
                  const val = e.target.value.replace(/\D/g, '').slice(0, 4);
                  setLast4Value(val);
                }}
                placeholder="0000"
                className={cn(
                  'mt-1 w-full rounded-md border px-3 py-2 text-center text-2xl font-mono tracking-[0.5em]',
                )}
                maxLength={4}
                inputMode="numeric"
                autoFocus
              />
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={resetForm}
                className="flex-1"
              >
                Back
              </Button>
              <Button
                type="submit"
                size="sm"
                disabled={last4Value.length !== 4 || logEncounter.isPending}
                className="flex-1"
              >
                {logEncounter.isPending && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
                Log
              </Button>
            </div>
          </form>
        )}

        {/* Error display */}
        {logEncounter.isError && (
          <p className="text-xs text-destructive text-center">
            {logEncounter.error instanceof Error
              ? logEncounter.error.message
              : 'Failed to log encounter'}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
