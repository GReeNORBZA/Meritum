'use client';

import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { useMarkAsRead, useDismissNotification } from '@/hooks/api/use-notifications';
import type { Notification, NotificationCategory } from '@/hooks/api/use-notifications';
import { cn } from '@/lib/utils';
import {
  FileText,
  DollarSign,
  Settings,
  X,
  Loader2,
} from 'lucide-react';

// ---------- Helpers ----------

const CATEGORY_ICONS: Record<NotificationCategory, React.ReactNode> = {
  claims: <FileText className="h-4 w-4 text-blue-600" />,
  billing: <DollarSign className="h-4 w-4 text-green-600" />,
  system: <Settings className="h-4 w-4 text-gray-500" />,
};

function getRelativeTime(dateStr: string): string {
  const now = new Date();
  const date = new Date(dateStr);
  const diffMs = now.getTime() - date.getTime();
  const diffSeconds = Math.floor(diffMs / 1000);
  const diffMinutes = Math.floor(diffSeconds / 60);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSeconds < 60) return 'just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

function getNavigationPath(relatedType?: string, relatedId?: string): string | null {
  if (!relatedType || !relatedId) return null;

  switch (relatedType) {
    case 'claim':
      return `/claims/${relatedId}`;
    case 'batch':
      return `/batches/${relatedId}`;
    case 'patient':
      return `/patients/${relatedId}`;
    default:
      return null;
  }
}

// ---------- Types ----------

interface NotificationItemProps {
  notification: Notification;
}

// ---------- Component ----------

function NotificationItem({ notification }: NotificationItemProps) {
  const router = useRouter();
  const markAsRead = useMarkAsRead();
  const dismissNotification = useDismissNotification();

  const icon = CATEGORY_ICONS[notification.category] ?? CATEGORY_ICONS.system;
  const navigationPath = getNavigationPath(notification.related_type, notification.related_id);

  const handleClick = () => {
    if (!notification.is_read) {
      markAsRead.mutate(notification.id);
    }
    if (navigationPath) {
      router.push(navigationPath);
    }
  };

  const handleDismiss = (e: React.MouseEvent) => {
    e.stopPropagation();
    dismissNotification.mutate(notification.id);
  };

  return (
    <div
      className={cn(
        'group flex items-start gap-3 rounded-md px-3 py-3 transition-colors',
        navigationPath && 'cursor-pointer hover:bg-muted/50',
        !notification.is_read && 'bg-muted/30',
      )}
      onClick={handleClick}
      role={navigationPath ? 'button' : undefined}
      tabIndex={navigationPath ? 0 : undefined}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleClick();
        }
      }}
    >
      {/* Unread indicator */}
      <div className="mt-1.5 flex shrink-0 items-center gap-2">
        {!notification.is_read && (
          <span className="h-2 w-2 rounded-full bg-primary" />
        )}
        {notification.is_read && <span className="h-2 w-2" />}
        {icon}
      </div>

      {/* Content */}
      <div className="min-w-0 flex-1">
        <p
          className={cn(
            'text-sm leading-snug',
            !notification.is_read && 'font-medium',
          )}
        >
          {notification.title}
        </p>
        <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
          {notification.message}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {getRelativeTime(notification.created_at)}
        </p>
      </div>

      {/* Dismiss button */}
      <Button
        variant="ghost"
        size="sm"
        className="h-7 w-7 shrink-0 p-0 opacity-0 group-hover:opacity-100"
        onClick={handleDismiss}
        disabled={dismissNotification.isPending}
      >
        {dismissNotification.isPending ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <X className="h-3.5 w-3.5" />
        )}
        <span className="sr-only">Dismiss</span>
      </Button>
    </div>
  );
}

export { NotificationItem };
export type { NotificationItemProps };
