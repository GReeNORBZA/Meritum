'use client';

import * as React from 'react';
import { useSubmitFeedback } from '@/hooks/api/use-support';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { ThumbsUp, ThumbsDown, CheckCircle2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ArticleFeedbackProps {
  slug: string;
  className?: string;
}

function ArticleFeedback({ slug, className }: ArticleFeedbackProps) {
  const [submitted, setSubmitted] = React.useState(false);
  const [showCommentForm, setShowCommentForm] = React.useState(false);
  const [comment, setComment] = React.useState('');

  const feedbackMutation = useSubmitFeedback();

  const handleFeedback = (helpful: boolean) => {
    if (helpful) {
      feedbackMutation.mutate(
        { slug, helpful: true },
        {
          onSuccess: () => setSubmitted(true),
        }
      );
    } else {
      setShowCommentForm(true);
    }
  };

  const handleSubmitNegativeFeedback = () => {
    feedbackMutation.mutate(
      { slug, helpful: false, comment: comment || undefined },
      {
        onSuccess: () => {
          setSubmitted(true);
          setShowCommentForm(false);
        },
      }
    );
  };

  if (submitted) {
    return (
      <div className={cn('flex items-center gap-2 rounded-lg border bg-muted/50 p-4', className)}>
        <CheckCircle2 className="h-5 w-5 text-success" />
        <span className="text-sm text-muted-foreground">
          Thank you for your feedback!
        </span>
      </div>
    );
  }

  return (
    <div className={cn('rounded-lg border p-4', className)}>
      {!showCommentForm ? (
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">Was this article helpful?</span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleFeedback(true)}
              disabled={feedbackMutation.isPending}
            >
              <ThumbsUp className="mr-1.5 h-4 w-4" />
              Yes
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleFeedback(false)}
              disabled={feedbackMutation.isPending}
            >
              <ThumbsDown className="mr-1.5 h-4 w-4" />
              No
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm font-medium">
            Sorry to hear that. How can we improve this article?
          </p>
          <Textarea
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="Tell us what was missing or unclear..."
            rows={3}
          />
          <div className="flex items-center gap-2 justify-end">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setShowCommentForm(false);
                setComment('');
              }}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSubmitNegativeFeedback}
              disabled={feedbackMutation.isPending}
            >
              {feedbackMutation.isPending ? 'Submitting...' : 'Submit Feedback'}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export { ArticleFeedback };
