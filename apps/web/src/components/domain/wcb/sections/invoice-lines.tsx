'use client';

import * as React from 'react';
import { useFormContext, useFieldArray } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DatePicker } from '@/components/forms/date-picker';
import { Separator } from '@/components/ui/separator';
import { Plus, Trash2, Receipt } from 'lucide-react';

interface InvoiceLinesSectionProps {
  readOnly?: boolean;
  formType?: string;
}

const LINE_TYPES = [
  { value: 'STANDARD', label: 'Standard' },
  { value: 'DATED', label: 'Dated (Date Range)' },
  { value: 'SUPPLY', label: 'Supply' },
  { value: 'WAS', label: 'WAS (Correction - Original)' },
  { value: 'SHOULD_BE', label: 'SHOULD BE (Correction - New)' },
] as const;

function getDefaultLine(lineType: string) {
  switch (lineType) {
    case 'SUPPLY':
      return {
        line_type: 'SUPPLY',
        quantity: 1,
        supply_description: '',
        amount: '',
      };
    case 'WAS':
    case 'SHOULD_BE':
      return {
        line_type: lineType,
        correction_pair_id: 1,
        health_service_code: '',
        amount: '',
      };
    case 'DATED':
      return {
        line_type: 'DATED',
        health_service_code: '',
        date_of_service_from: '',
        date_of_service_to: '',
        amount: '',
      };
    default:
      return {
        line_type: 'STANDARD',
        health_service_code: '',
        calls: 1,
        encounters: 1,
      };
  }
}

// ---------- Standard Line ----------

function StandardLineFields({
  index,
  readOnly,
}: {
  index: number;
  readOnly?: boolean;
}) {
  const { register } = useFormContext();

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="space-y-1">
        <Label className="text-xs">HSC Code</Label>
        <Input
          maxLength={7}
          placeholder="e.g. 03.01A"
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.health_service_code`)}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Calls</Label>
        <Input
          type="number"
          min={1}
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.calls`, { valueAsNumber: true })}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Encounters</Label>
        <Input
          type="number"
          min={1}
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.encounters`, {
            valueAsNumber: true,
          })}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Diagnostic Code 1</Label>
        <Input
          maxLength={8}
          placeholder="ICD code"
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.diagnostic_code_1`)}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Modifier 1</Label>
        <Input
          maxLength={6}
          placeholder="Modifier"
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.modifier_1`)}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Modifier 2</Label>
        <Input
          maxLength={6}
          placeholder="Modifier"
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.modifier_2`)}
        />
      </div>
    </div>
  );
}

// ---------- Dated Line ----------

function DatedLineFields({
  index,
  readOnly,
}: {
  index: number;
  readOnly?: boolean;
}) {
  const { register, watch, setValue } = useFormContext();

  const dateFrom = watch(`invoice_lines.${index}.date_of_service_from`);
  const dateTo = watch(`invoice_lines.${index}.date_of_service_to`);

  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-1">
          <Label className="text-xs">HSC Code</Label>
          <Input
            maxLength={7}
            placeholder="e.g. 03.01A"
            className="font-mono"
            readOnly={readOnly}
            {...register(`invoice_lines.${index}.health_service_code`)}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Service Date From</Label>
          <DatePicker
            value={dateFrom ? new Date(dateFrom) : undefined}
            onChange={(d) =>
              setValue(
                `invoice_lines.${index}.date_of_service_from`,
                d ? d.toISOString().split('T')[0] : ''
              )
            }
            placeholder="From..."
            disabled={readOnly}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Service Date To</Label>
          <DatePicker
            value={dateTo ? new Date(dateTo) : undefined}
            onChange={(d) =>
              setValue(
                `invoice_lines.${index}.date_of_service_to`,
                d ? d.toISOString().split('T')[0] : ''
              )
            }
            placeholder="To..."
            disabled={readOnly}
          />
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-1">
          <Label className="text-xs">Amount ($)</Label>
          <Input
            placeholder="0.00"
            className="font-mono"
            readOnly={readOnly}
            {...register(`invoice_lines.${index}.amount`)}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Diagnostic Code 1</Label>
          <Input
            maxLength={8}
            className="font-mono"
            readOnly={readOnly}
            {...register(`invoice_lines.${index}.diagnostic_code_1`)}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Modifier 1</Label>
          <Input
            maxLength={6}
            className="font-mono"
            readOnly={readOnly}
            {...register(`invoice_lines.${index}.modifier_1`)}
          />
        </div>
      </div>
    </div>
  );
}

// ---------- Supply Line ----------

function SupplyLineFields({
  index,
  readOnly,
}: {
  index: number;
  readOnly?: boolean;
}) {
  const { register } = useFormContext();

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="space-y-1">
        <Label className="text-xs">Description</Label>
        <Input
          maxLength={50}
          placeholder="Supply description"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.supply_description`)}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Quantity</Label>
        <Input
          type="number"
          min={1}
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.quantity`, {
            valueAsNumber: true,
          })}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Amount ($)</Label>
        <Input
          placeholder="0.00"
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.amount`)}
        />
      </div>
    </div>
  );
}

// ---------- Correction Line ----------

function CorrectionLineFields({
  index,
  readOnly,
}: {
  index: number;
  readOnly?: boolean;
}) {
  const { register } = useFormContext();

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="space-y-1">
        <Label className="text-xs">Correction Pair ID</Label>
        <Input
          type="number"
          min={1}
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.correction_pair_id`, {
            valueAsNumber: true,
          })}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">HSC Code</Label>
        <Input
          maxLength={7}
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.health_service_code`)}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Amount ($)</Label>
        <Input
          placeholder="0.00"
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.amount`)}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Diagnostic Code 1</Label>
        <Input
          maxLength={8}
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.diagnostic_code_1`)}
        />
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Modifier 1</Label>
        <Input
          maxLength={6}
          className="font-mono"
          readOnly={readOnly}
          {...register(`invoice_lines.${index}.modifier_1`)}
        />
      </div>
    </div>
  );
}

// ---------- Main Section ----------

function InvoiceLinesSection({ readOnly, formType }: InvoiceLinesSectionProps) {
  const { control, watch, setValue } = useFormContext();

  const { fields, append, remove } = useFieldArray({
    control,
    name: 'invoice_lines',
  });

  // Determine allowed line types based on form type
  const allowedLineTypes = React.useMemo(() => {
    if (formType === 'C569') {
      return LINE_TYPES.filter((t) => t.value === 'SUPPLY');
    }
    if (formType === 'C570') {
      return LINE_TYPES.filter(
        (t) => t.value === 'WAS' || t.value === 'SHOULD_BE'
      );
    }
    return LINE_TYPES.filter(
      (t) => t.value === 'STANDARD' || t.value === 'DATED'
    );
  }, [formType]);

  const [addLineType, setAddLineType] = React.useState(
    allowedLineTypes[0]?.value || 'STANDARD'
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Receipt className="h-5 w-5" />
          Invoice Lines
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {fields.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No invoice lines added. Add at least one line item.
          </p>
        )}

        {fields.map((field, index) => {
          const lineType = watch(`invoice_lines.${index}.line_type`);
          return (
            <div key={field.id} className="rounded-lg border p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Line #{index + 1}</span>
                  <Badge variant="outline" className="text-xs">
                    {lineType}
                  </Badge>
                </div>
                {!readOnly && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => remove(index)}
                    className="text-destructive hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>

              {lineType === 'STANDARD' && (
                <StandardLineFields index={index} readOnly={readOnly} />
              )}
              {lineType === 'DATED' && (
                <DatedLineFields index={index} readOnly={readOnly} />
              )}
              {lineType === 'SUPPLY' && (
                <SupplyLineFields index={index} readOnly={readOnly} />
              )}
              {(lineType === 'WAS' || lineType === 'SHOULD_BE') && (
                <CorrectionLineFields index={index} readOnly={readOnly} />
              )}
            </div>
          );
        })}

        {!readOnly && fields.length < 25 && (
          <>
            <Separator />
            <div className="flex items-end gap-2">
              <div className="space-y-1 flex-1 max-w-[200px]">
                <Label className="text-xs">Line Type</Label>
                <Select
                  value={addLineType}
                  onValueChange={(v) => setAddLineType(v as typeof addLineType)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {allowedLineTypes.map((lt) => (
                      <SelectItem key={lt.value} value={lt.value}>
                        {lt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => append(getDefaultLine(addLineType))}
              >
                <Plus className="mr-1 h-3 w-3" />
                Add Line
              </Button>
            </div>
          </>
        )}

        {fields.length >= 25 && (
          <p className="text-xs text-muted-foreground">
            Maximum of 25 invoice lines reached.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export { InvoiceLinesSection };
export type { InvoiceLinesSectionProps };
