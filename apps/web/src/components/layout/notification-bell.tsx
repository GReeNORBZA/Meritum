'use client';

import { useState } from 'react';
import { useUnreadCount } from '@/hooks/api/use-notifications';
import { NotificationFeed } from '@/components/domain/notifications/notification-feed';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Bell } from 'lucide-react';

// ---------- Component ----------

function NotificationBell() {
  const [feedOpen, setFeedOpen] = useState(false);
  const { data } = useUnreadCount();

  const unreadCount = data?.data?.count ?? 0;

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="relative h-9 w-9 p-0"
        onClick={() => setFeedOpen(true)}
        aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ''}`}
      >
        <Bell className="h-5 w-5" />
        {unreadCount > 0 && (
          <span
            className={cn(
              'absolute -right-0.5 -top-0.5 flex items-center justify-center rounded-full bg-destructive text-destructive-foreground text-[10px] font-bold leading-none',
              unreadCount > 99 ? 'h-5 w-7 px-1' : 'h-4.5 w-4.5 min-w-[18px] px-1',
            )}
          >
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </Button>

      <NotificationFeed open={feedOpen} onOpenChange={setFeedOpen} />
    </>
  );
}

export { NotificationBell };
