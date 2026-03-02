'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useCreateTicket } from '@/hooks/api/use-support';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { FileUpload } from '@/components/forms/file-upload';
import { ArrowLeft, Send } from 'lucide-react';

// ---------- Constants ----------

const TICKET_CATEGORIES = [
  { value: 'billing', label: 'Billing' },
  { value: 'technical', label: 'Technical' },
  { value: 'claims', label: 'Claims' },
  { value: 'account', label: 'Account' },
  { value: 'other', label: 'Other' },
] as const;

type TicketCategory = (typeof TICKET_CATEGORIES)[number]['value'];

// ---------- Browser Context ----------

function getBrowserContext() {
  if (typeof window === 'undefined') {
    return { page_url: '', browser_info: '' };
  }
  return {
    page_url: window.location.href,
    browser_info: navigator.userAgent,
  };
}

// ---------- Main Page ----------

export default function NewTicketPage() {
  const router = useRouter();
  const createTicket = useCreateTicket();

  const [subject, setSubject] = React.useState('');
  const [category, setCategory] = React.useState<TicketCategory | ''>('');
  const [description, setDescription] = React.useState('');
  const [attachments, setAttachments] = React.useState<File[]>([]);
  const [errors, setErrors] = React.useState<Record<string, string>>({});

  const validate = (): boolean => {
    const newErrors: Record<string, string> = {};
    if (!subject.trim()) newErrors.subject = 'Subject is required';
    if (!category) newErrors.category = 'Category is required';
    if (!description.trim()) newErrors.description = 'Description is required';
    if (description.trim().length < 20) {
      newErrors.description = 'Please provide at least 20 characters of detail';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    const context = getBrowserContext();

    createTicket.mutate(
      {
        subject: subject.trim(),
        category: category as TicketCategory,
        description: description.trim(),
        attachments: attachments.length > 0 ? attachments : undefined,
        context,
      },
      {
        onSuccess: (response) => {
          const ticket = response.data;
          router.push(ROUTES.SUPPORT_TICKET_DETAIL(ticket.id));
        },
      }
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          href={ROUTES.SUPPORT_TICKETS}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Tickets
        </Link>
        <h1 className="text-3xl font-bold tracking-tight">Submit a Support Ticket</h1>
        <p className="text-muted-foreground">
          Describe your issue and our team will get back to you as soon as possible
        </p>
      </div>

      {/* Form */}
      <Card>
        <CardHeader>
          <CardTitle>Ticket Details</CardTitle>
          <CardDescription>
            Please provide as much detail as possible to help us resolve your issue quickly.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Subject */}
            <div className="space-y-2">
              <Label htmlFor="subject">
                Subject <span className="text-destructive">*</span>
              </Label>
              <Input
                id="subject"
                value={subject}
                onChange={(e) => {
                  setSubject(e.target.value);
                  if (errors.subject) setErrors((prev) => ({ ...prev, subject: '' }));
                }}
                placeholder="Brief summary of your issue"
                maxLength={200}
              />
              {errors.subject && (
                <p className="text-xs text-destructive">{errors.subject}</p>
              )}
            </div>

            {/* Category */}
            <div className="space-y-2">
              <Label htmlFor="category">
                Category <span className="text-destructive">*</span>
              </Label>
              <Select
                value={category}
                onValueChange={(val) => {
                  setCategory(val as TicketCategory);
                  if (errors.category) setErrors((prev) => ({ ...prev, category: '' }));
                }}
              >
                <SelectTrigger id="category">
                  <SelectValue placeholder="Select a category" />
                </SelectTrigger>
                <SelectContent>
                  {TICKET_CATEGORIES.map((cat) => (
                    <SelectItem key={cat.value} value={cat.value}>
                      {cat.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {errors.category && (
                <p className="text-xs text-destructive">{errors.category}</p>
              )}
            </div>

            {/* Description */}
            <div className="space-y-2">
              <Label htmlFor="description">
                Description <span className="text-destructive">*</span>
              </Label>
              <Textarea
                id="description"
                value={description}
                onChange={(e) => {
                  setDescription(e.target.value);
                  if (errors.description) setErrors((prev) => ({ ...prev, description: '' }));
                }}
                placeholder="Describe your issue in detail. Include steps to reproduce, expected behavior, and what actually happened."
                rows={6}
              />
              <div className="flex items-center justify-between">
                {errors.description ? (
                  <p className="text-xs text-destructive">{errors.description}</p>
                ) : (
                  <span />
                )}
                <span className="text-xs text-muted-foreground">
                  {description.length} characters
                </span>
              </div>
            </div>

            {/* Screenshots / Attachments */}
            <div className="space-y-2">
              <Label>Screenshots (optional)</Label>
              <FileUpload
                accept="image/*,.pdf"
                maxSize={10 * 1024 * 1024}
                maxFiles={5}
                onUpload={setAttachments}
              />
            </div>

            {/* Context Info */}
            <div className="rounded-lg bg-muted/50 p-3 text-xs text-muted-foreground">
              <p className="font-medium mb-1">Automatically included context:</p>
              <ul className="list-disc list-inside space-y-0.5">
                <li>Current page URL</li>
                <li>Browser information</li>
              </ul>
              <p className="mt-1">
                This helps our support team diagnose your issue faster.
              </p>
            </div>

            {/* Submit */}
            <div className="flex items-center gap-3 justify-end">
              <Link href={ROUTES.SUPPORT_TICKETS}>
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </Link>
              <Button type="submit" disabled={createTicket.isPending}>
                <Send className="mr-2 h-4 w-4" />
                {createTicket.isPending ? 'Submitting...' : 'Submit Ticket'}
              </Button>
            </div>

            {createTicket.isError && (
              <p className="text-sm text-destructive">
                Failed to submit ticket. Please try again.
              </p>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
