'use client';

import * as React from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { ROUTES } from '@/config/routes';
import { WcbFormBuilder } from '@/components/domain/wcb/wcb-form-builder';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ArrowLeft, FileText } from 'lucide-react';

// ---------- Form Type Cards ----------

const WCB_FORM_CARDS = [
  {
    formType: 'C050E',
    name: "Physician's First Report",
    code: 'C050',
    description:
      'Initial physician report for a new WCB claim. Used by GPs, ER specialists, and nurse practitioners to document the first examination of a workplace injury.',
    fieldCount: 111,
    isInitial: true,
  },
  {
    formType: 'C050S',
    name: "Physician's First Report - Specialist (OIS)",
    code: 'C050S',
    description:
      'Initial physician report with Occupational Injury Service (OIS) appendix. Includes comprehensive functional capacity and return-to-work assessment.',
    fieldCount: 171,
    isInitial: true,
  },
  {
    formType: 'C151',
    name: "Physician's Progress Report",
    code: 'C151',
    description:
      'Follow-up progress report on an existing WCB claim. Documents ongoing treatment, updated diagnosis, and return-to-work status.',
    fieldCount: 136,
    isInitial: false,
  },
  {
    formType: 'C151S',
    name: "Physician's Progress Report - Specialist (OIS)",
    code: 'C151S',
    description:
      'Follow-up progress report with OIS appendix. Includes updated functional capacity assessment and modified work recommendations.',
    fieldCount: 153,
    isInitial: false,
  },
  {
    formType: 'C568A',
    name: 'Referral / Consultation Report',
    code: 'C080',
    description:
      'Consultation report and invoice for specialist assessment. Used by specialists and surgeons for referral-based consultations.',
    fieldCount: 69,
    isInitial: false,
  },
  {
    formType: 'C568',
    name: 'Surgical Report',
    code: 'C082',
    description:
      'Medical invoice for surgical and medical services rendered under a WCB claim. Standard billing form for procedures.',
    fieldCount: 61,
    isInitial: false,
  },
  {
    formType: 'C569',
    name: 'Occupational Injury Service',
    code: 'C137',
    description:
      'Invoice for medical supplies provided under a WCB claim. Used for supply items, equipment, and materials.',
    fieldCount: 37,
    isInitial: false,
  },
  {
    formType: 'C570',
    name: 'Certification of Fitness',
    code: 'C200',
    description:
      'Correction to a previously submitted medical invoice. Used to fix billing errors with WAS/SHOULD BE correction pairs.',
    fieldCount: 66,
    isInitial: false,
  },
] as const;

// ---------- Form Type Selector ----------

function FormTypeSelector({
  onSelect,
}: {
  onSelect: (formType: string) => void;
}) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">New WCB Claim</h1>
        <p className="text-muted-foreground">
          Select the form type to begin creating a new WCB claim
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {WCB_FORM_CARDS.map((card) => (
          <Card
            key={card.formType}
            className="cursor-pointer transition-all hover:border-primary hover:shadow-md"
            onClick={() => onSelect(card.formType)}
          >
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <Badge
                  variant="outline"
                  className="font-mono text-xs"
                >
                  {card.code}
                </Badge>
                {card.isInitial && (
                  <Badge variant="default" className="text-xs">
                    Initial
                  </Badge>
                )}
              </div>
              <CardTitle className="mt-2 text-base">{card.name}</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-xs leading-relaxed">
                {card.description}
              </CardDescription>
              <p className="mt-3 text-xs text-muted-foreground">
                {card.fieldCount} fields
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ---------- Main Page ----------

function NewWcbClaimPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const formTypeParam = searchParams.get('formType');

  const [selectedFormType, setSelectedFormType] = React.useState<string | null>(
    formTypeParam
  );

  const handleSelectFormType = React.useCallback(
    (formType: string) => {
      setSelectedFormType(formType);
      router.replace(`${ROUTES.WCB_NEW}?formType=${formType}`, { scroll: false });
    },
    [router]
  );

  if (!selectedFormType) {
    return <FormTypeSelector onSelect={handleSelectFormType} />;
  }

  const selectedCard = WCB_FORM_CARDS.find((c) => c.formType === selectedFormType);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setSelectedFormType(null)}
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight">
              New WCB Claim
            </h1>
            <Badge variant="outline" className="font-mono">
              {selectedFormType}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            {selectedCard?.name || selectedFormType}
          </p>
        </div>
      </div>

      {/* Form Builder */}
      <WcbFormBuilder formType={selectedFormType} />
    </div>
  );
}

export default function NewWcbClaimPage() {
  return (
    <React.Suspense>
      <NewWcbClaimPageContent />
    </React.Suspense>
  );
}
