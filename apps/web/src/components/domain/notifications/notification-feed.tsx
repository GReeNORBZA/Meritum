'use client';

import { useState } from 'react';
import {
  useNotifications,
  useMarkAllAsRead,
  type NotificationCategory,
} from '@/hooks/api/use-notifications';
import { NotificationItem } from './notification-item';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import { Loader2, CheckCheck, Inbox } from 'lucide-react';

// ---------- Types ----------

type CategoryTab = 'all' | NotificationCategory;

interface NotificationFeedProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// ---------- Component ----------

function NotificationFeed({ open, onOpenChange }: NotificationFeedProps) {
  const [activeTab, setActiveTab] = useState<CategoryTab>('all');
  const [page, setPage] = useState(1);

  const categoryFilter = activeTab === 'all' ? undefined : activeTab;

  const { data, isLoading } = useNotifications({
    category: categoryFilter,
    page,
    pageSize: 20,
  });
  const markAllAsRead = useMarkAllAsRead();

  const notifications = data?.data ?? [];
  const pagination = data?.pagination;
  const hasMore = pagination?.hasMore ?? false;

  const handleTabChange = (value: string) => {
    setActiveTab(value as CategoryTab);
    setPage(1);
  };

  const handleMarkAllAsRead = () => {
    markAllAsRead.mutate();
  };

  const handleLoadMore = () => {
    setPage((prev) => prev + 1);
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader>
          <div className="flex items-center justify-between pr-6">
            <SheetTitle>Notifications</SheetTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleMarkAllAsRead}
              disabled={markAllAsRead.isPending || notifications.length === 0}
            >
              {markAllAsRead.isPending ? (
                <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              ) : (
                <CheckCheck className="mr-1.5 h-3.5 w-3.5" />
              )}
              Mark all read
            </Button>
          </div>
          <SheetDescription>
            Stay up to date with your claims and billing activity
          </SheetDescription>
        </SheetHeader>

        <Tabs
          value={activeTab}
          onValueChange={handleTabChange}
          className="mt-4"
        >
          <TabsList className="w-full">
            <TabsTrigger value="all" className="flex-1">
              All
            </TabsTrigger>
            <TabsTrigger value="claims" className="flex-1">
              Claims
            </TabsTrigger>
            <TabsTrigger value="billing" className="flex-1">
              Billing
            </TabsTrigger>
            <TabsTrigger value="system" className="flex-1">
              System
            </TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab} className="mt-3">
            <ScrollArea className="h-[calc(100vh-220px)]">
              {isLoading && (
                <div className="space-y-3 px-1">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex items-start gap-3 p-3">
                      <Skeleton className="h-4 w-4 shrink-0 rounded-full" />
                      <div className="flex-1 space-y-2">
                        <Skeleton className="h-4 w-3/4" />
                        <Skeleton className="h-3 w-full" />
                        <Skeleton className="h-3 w-20" />
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {!isLoading && notifications.length === 0 && (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <Inbox className="h-10 w-10 text-muted-foreground/50" />
                  <p className="mt-3 text-sm font-medium">No notifications</p>
                  <p className="text-xs text-muted-foreground">
                    You&apos;re all caught up
                  </p>
                </div>
              )}

              {!isLoading && notifications.length > 0 && (
                <div className="space-y-1">
                  {notifications.map((notification, index) => (
                    <div key={notification.id}>
                      <NotificationItem notification={notification} />
                      {index < notifications.length - 1 && (
                        <Separator className="mx-3" />
                      )}
                    </div>
                  ))}

                  {hasMore && (
                    <div className="flex justify-center py-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={handleLoadMore}
                      >
                        Load more
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
}

export { NotificationFeed };
export type { NotificationFeedProps };
