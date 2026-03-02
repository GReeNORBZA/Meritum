'use client';

import { useState } from 'react';
import { Card, CardContent, CardFooter, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Loader2, Download } from 'lucide-react';

interface StepImaAcknowledgementProps {
  onNext: (payload: Record<string, unknown>) => void;
  onBack?: () => void;
}

const IMA_DOCUMENT_HASH = '0'.repeat(64);

export function StepImaAcknowledgement({ onNext, onBack }: StepImaAcknowledgementProps) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!acknowledged) return;
    setIsSubmitting(true);
    try {
      await onNext({ document_hash: IMA_DOCUMENT_HASH });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDownload = () => {
    window.open('/api/v1/onboarding/ima/download', '_blank');
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>IMA Acknowledgement</CardTitle>
        <CardDescription>
          Please review and acknowledge the Information Manager Agreement (IMA) as required by Alberta Health for electronic claim submissions.
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          <div className="rounded-md border bg-muted/50 p-4 space-y-3 text-sm">
            <h3 className="font-semibold">Information Manager Agreement (AHC 11236)</h3>
            <p>
              This agreement is required under the Health Information Act (HIA) of Alberta. By using Meritum
              to submit claims electronically on your behalf, you acknowledge and agree to the following:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>
                Meritum acts as an Information Manager under the HIA and will handle your health
                information in accordance with the Act.
              </li>
              <li>
                You retain full responsibility for the accuracy and completeness of all claims
                submitted through the platform.
              </li>
              <li>
                Meritum will maintain appropriate safeguards to protect health information from
                unauthorized access, use, or disclosure.
              </li>
              <li>
                You agree to notify Meritum promptly of any changes to your practice information
                that may affect claim submissions.
              </li>
              <li>
                This agreement remains in effect for the duration of your use of the Meritum
                platform and may be terminated by either party with written notice.
              </li>
            </ul>
          </div>

          <Button type="button" variant="outline" onClick={handleDownload} className="w-full">
            <Download className="mr-2 h-4 w-4" />
            Download AHC 11236 Form (PDF)
          </Button>

          <div className="flex items-start space-x-2 pt-2">
            <Checkbox
              id="acknowledged"
              checked={acknowledged}
              onCheckedChange={(checked) => setAcknowledged(checked === true)}
              className="mt-0.5"
            />
            <Label htmlFor="acknowledged" className="cursor-pointer leading-relaxed">
              I have read and acknowledge the Information Manager Agreement (IMA). I understand that
              this agreement is required for electronic claim submission through Meritum.
            </Label>
          </div>
        </CardContent>
        <CardFooter className="flex justify-between">
          <Button type="button" variant="outline" onClick={onBack}>
            Back
          </Button>
          <Button type="submit" disabled={isSubmitting || !acknowledged}>
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Complete Setup
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
