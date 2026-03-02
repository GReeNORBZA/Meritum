'use client';

import * as React from 'react';
import { useSubmitRating } from '@/hooks/api/use-support';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Star, CheckCircle2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SatisfactionRatingProps {
  ticketId: string;
  existingRating?: { score: number; comment?: string } | null;
  className?: string;
}

function SatisfactionRating({ ticketId, existingRating, className }: SatisfactionRatingProps) {
  const [score, setScore] = React.useState(existingRating?.score ?? 0);
  const [hoveredStar, setHoveredStar] = React.useState(0);
  const [comment, setComment] = React.useState(existingRating?.comment ?? '');
  const [submitted, setSubmitted] = React.useState(!!existingRating);

  const ratingMutation = useSubmitRating();

  const handleSubmit = () => {
    if (score === 0) return;

    ratingMutation.mutate(
      { id: ticketId, score, comment: comment || undefined },
      {
        onSuccess: () => setSubmitted(true),
      }
    );
  };

  if (submitted) {
    return (
      <div className={cn('rounded-lg border bg-muted/50 p-4', className)}>
        <div className="flex items-center gap-2 mb-2">
          <CheckCircle2 className="h-5 w-5 text-success" />
          <span className="text-sm font-medium">Thank you for your rating!</span>
        </div>
        <div className="flex items-center gap-0.5">
          {[1, 2, 3, 4, 5].map((star) => (
            <Star
              key={star}
              className={cn(
                'h-5 w-5',
                star <= (existingRating?.score ?? score)
                  ? 'fill-yellow-400 text-yellow-400'
                  : 'text-muted-foreground'
              )}
            />
          ))}
        </div>
        {(existingRating?.comment || comment) && (
          <p className="mt-2 text-sm text-muted-foreground">
            {existingRating?.comment || comment}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className={cn('rounded-lg border p-4 space-y-4', className)}>
      <div>
        <p className="text-sm font-medium mb-2">How would you rate the support you received?</p>
        <div className="flex items-center gap-1">
          {[1, 2, 3, 4, 5].map((star) => (
            <button
              key={star}
              type="button"
              onClick={() => setScore(star)}
              onMouseEnter={() => setHoveredStar(star)}
              onMouseLeave={() => setHoveredStar(0)}
              className="focus:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-sm p-0.5 transition-transform hover:scale-110"
            >
              <Star
                className={cn(
                  'h-7 w-7 transition-colors',
                  star <= (hoveredStar || score)
                    ? 'fill-yellow-400 text-yellow-400'
                    : 'text-muted-foreground hover:text-yellow-300'
                )}
              />
            </button>
          ))}
          {score > 0 && (
            <span className="ml-2 text-sm text-muted-foreground">
              {score === 1 && 'Poor'}
              {score === 2 && 'Fair'}
              {score === 3 && 'Good'}
              {score === 4 && 'Very Good'}
              {score === 5 && 'Excellent'}
            </span>
          )}
        </div>
      </div>

      <div>
        <Textarea
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="Any additional feedback? (optional)"
          rows={3}
        />
      </div>

      <div className="flex justify-end">
        <Button
          onClick={handleSubmit}
          disabled={score === 0 || ratingMutation.isPending}
          size="sm"
        >
          {ratingMutation.isPending ? 'Submitting...' : 'Submit Rating'}
        </Button>
      </div>
    </div>
  );
}

export { SatisfactionRating };
