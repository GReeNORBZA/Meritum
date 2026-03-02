'use client';

import * as React from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useTicket, useReplyToTicket, type TicketMessage } from '@/hooks/api/use-support';
import { ROUTES } from '@/config/routes';
import { SatisfactionRating } from '@/components/domain/support/satisfaction-rating';
import { StatusBadge } from '@/components/shared/status-badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Separator } from '@/components/ui/separator';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Skeleton } from '@/components/ui/skeleton';
import { formatDateTime, formatRelative } from '@/lib/formatters/date';
import {
  ArrowLeft,
  Send,
  User,
  Headphones,
  CheckCircle2,
  Circle,
  Clock,
  Paperclip,
} from 'lucide-react';
import { cn } from '@/lib/utils';

// ---------- Status Timeline ----------

const STATUS_STEPS = [
  { key: 'OPEN', label: 'Open', icon: Circle },
  { key: 'IN_PROGRESS', label: 'In Progress', icon: Clock },
  { key: 'RESOLVED', label: 'Resolved', icon: CheckCircle2 },
  { key: 'CLOSED', label: 'Closed', icon: CheckCircle2 },
] as const;

function getStatusIndex(status: string): number {
  if (status === 'PENDING') return 0;
  const idx = STATUS_STEPS.findIndex((s) => s.key === status);
  return idx === -1 ? 0 : idx;
}

const CATEGORY_LABELS: Record<string, string> = {
  billing: 'Billing',
  technical: 'Technical',
  claims: 'Claims',
  account: 'Account',
  other: 'Other',
};

// ---------- Message Bubble ----------

function MessageBubble({ message }: { message: TicketMessage }) {
  const isUser = message.sender_type === 'user';

  return (
    <div className={cn('flex gap-3', isUser ? 'flex-row-reverse' : '')}>
      <Avatar className="h-8 w-8 shrink-0">
        <AvatarFallback className={isUser ? 'bg-primary/10' : 'bg-blue-100 dark:bg-blue-900/30'}>
          {isUser ? (
            <User className="h-4 w-4" />
          ) : (
            <Headphones className="h-4 w-4" />
          )}
        </AvatarFallback>
      </Avatar>
      <div className={cn('max-w-[70%] space-y-1', isUser ? 'items-end' : '')}>
        <div className={cn('flex items-center gap-2', isUser ? 'flex-row-reverse' : '')}>
          <span className="text-xs font-medium">{message.sender_name}</span>
          <span className="text-xs text-muted-foreground">
            {formatRelative(message.created_at)}
          </span>
        </div>
        <div
          className={cn(
            'rounded-lg px-4 py-2.5 text-sm',
            isUser
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted'
          )}
        >
          <p className="whitespace-pre-wrap">{message.content}</p>
        </div>
        {message.attachments && message.attachments.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-1">
            {message.attachments.map((attachment) => (
              <a
                key={attachment.url}
                href={attachment.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 rounded bg-muted px-2 py-1 text-xs hover:bg-accent transition-colors"
              >
                <Paperclip className="h-3 w-3" />
                {attachment.name}
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------- Main Page ----------

export default function TicketDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const { data, isLoading } = useTicket(id);
  const ticket = data?.data;

  const replyMutation = useReplyToTicket();

  const [replyContent, setReplyContent] = React.useState('');

  const messagesEndRef = React.useRef<HTMLDivElement>(null);

  // Scroll to bottom when new messages arrive
  React.useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [ticket?.messages.length]);

  const handleReply = (e: React.FormEvent) => {
    e.preventDefault();
    if (!replyContent.trim()) return;

    replyMutation.mutate(
      { id, content: replyContent.trim() },
      {
        onSuccess: () => setReplyContent(''),
      }
    );
  };

  const isResolved = ticket?.status === 'RESOLVED' || ticket?.status === 'CLOSED';
  const currentStatusIndex = ticket ? getStatusIndex(ticket.status) : 0;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-8 w-2/3" />
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_300px]">
          <div className="space-y-4">
            <Skeleton className="h-32 w-full" />
            <Skeleton className="h-32 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    );
  }

  if (!ticket) {
    return (
      <div className="space-y-4">
        <Link
          href={ROUTES.SUPPORT_TICKETS}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Tickets
        </Link>
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">Ticket not found.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Back Link */}
      <Link
        href={ROUTES.SUPPORT_TICKETS}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Tickets
      </Link>

      {/* Ticket Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-2xl font-bold tracking-tight">{ticket.subject}</h1>
            <StatusBadge status={ticket.status} />
          </div>
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            <span className="font-mono">{ticket.ticket_number}</span>
            <Badge variant="outline" className="capitalize">
              {CATEGORY_LABELS[ticket.category] ?? ticket.category}
            </Badge>
            <span>Created {formatDateTime(ticket.created_at)}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_300px]">
        {/* Main Content */}
        <div className="space-y-6">
          {/* Message Thread */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Conversation</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {ticket.messages.map((message) => (
                  <MessageBubble key={message.id} message={message} />
                ))}
                <div ref={messagesEndRef} />
              </div>
            </CardContent>
          </Card>

          {/* Reply Form */}
          {!isResolved ? (
            <Card>
              <CardContent className="pt-6">
                <form onSubmit={handleReply} className="space-y-3">
                  <Textarea
                    value={replyContent}
                    onChange={(e) => setReplyContent(e.target.value)}
                    placeholder="Type your reply..."
                    rows={4}
                  />
                  <div className="flex justify-end">
                    <Button
                      type="submit"
                      disabled={!replyContent.trim() || replyMutation.isPending}
                      size="sm"
                    >
                      <Send className="mr-2 h-4 w-4" />
                      {replyMutation.isPending ? 'Sending...' : 'Send Reply'}
                    </Button>
                  </div>
                  {replyMutation.isError && (
                    <p className="text-sm text-destructive">
                      Failed to send reply. Please try again.
                    </p>
                  )}
                </form>
              </CardContent>
            </Card>
          ) : (
            /* Satisfaction Rating for resolved tickets */
            <SatisfactionRating
              ticketId={id}
              existingRating={ticket.rating}
            />
          )}
        </div>

        {/* Sidebar */}
        <aside className="space-y-4">
          {/* Status Timeline */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Status Tracking</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {STATUS_STEPS.map((step, index) => {
                  const StepIcon = step.icon;
                  const isComplete = index <= currentStatusIndex;
                  const isCurrent = index === currentStatusIndex;

                  return (
                    <div key={step.key} className="flex items-start gap-3">
                      <div className="relative flex flex-col items-center">
                        <div
                          className={cn(
                            'flex h-6 w-6 items-center justify-center rounded-full border-2',
                            isComplete
                              ? 'border-primary bg-primary text-primary-foreground'
                              : 'border-muted-foreground/30 text-muted-foreground/30'
                          )}
                        >
                          <StepIcon className="h-3 w-3" />
                        </div>
                        {index < STATUS_STEPS.length - 1 && (
                          <div
                            className={cn(
                              'w-0.5 h-6 mt-1',
                              index < currentStatusIndex
                                ? 'bg-primary'
                                : 'bg-muted-foreground/20'
                            )}
                          />
                        )}
                      </div>
                      <div className="pt-0.5">
                        <p
                          className={cn(
                            'text-sm font-medium',
                            isCurrent ? 'text-primary' : isComplete ? 'text-foreground' : 'text-muted-foreground'
                          )}
                        >
                          {step.label}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Ticket Details */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <p className="text-xs text-muted-foreground">Category</p>
                <p className="text-sm capitalize">
                  {CATEGORY_LABELS[ticket.category] ?? ticket.category}
                </p>
              </div>
              <Separator />
              <div>
                <p className="text-xs text-muted-foreground">Created</p>
                <p className="text-sm">{formatDateTime(ticket.created_at)}</p>
              </div>
              <Separator />
              <div>
                <p className="text-xs text-muted-foreground">Last Updated</p>
                <p className="text-sm">{formatRelative(ticket.updated_at)}</p>
              </div>
              {ticket.context?.page_url && (
                <>
                  <Separator />
                  <div>
                    <p className="text-xs text-muted-foreground">Submitted From</p>
                    <p className="text-sm truncate">{ticket.context.page_url}</p>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}
