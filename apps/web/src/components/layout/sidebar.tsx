'use client';

import Link from 'next/link';
import { PanelLeftClose, PanelLeft } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSidebarStore } from '@/stores/sidebar.store';
import { useAuthStore } from '@/stores/auth.store';
import { SidebarNav } from '@/components/layout/sidebar-nav';
import { mainNavItems, bottomNavItems, adminNavItems } from '@/config/navigation';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';

export function Sidebar() {
  const { isCollapsed, setCollapsed } = useSidebarStore();
  const { user } = useAuthStore();

  return (
    <aside
      className={cn(
        'hidden lg:flex flex-col border-r bg-sidebar transition-all duration-300',
        isCollapsed ? 'w-16' : 'w-64'
      )}
    >
      <div className={cn('flex h-14 items-center border-b px-4', isCollapsed && 'justify-center px-2')}>
        <Link href="/" className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold text-sm">
            M
          </div>
          {!isCollapsed && (
            <span className="text-lg font-semibold text-sidebar-foreground">Meritum</span>
          )}
        </Link>
      </div>

      <ScrollArea className="flex-1 py-4">
        <SidebarNav items={mainNavItems} collapsed={isCollapsed} />
        {user?.role === 'admin' && (
          <>
            <Separator className="my-4 mx-2" />
            <SidebarNav items={adminNavItems} collapsed={isCollapsed} />
          </>
        )}
      </ScrollArea>

      <div className="border-t py-2">
        <SidebarNav items={bottomNavItems} collapsed={isCollapsed} />
        <div className={cn('px-2 mt-2', isCollapsed && 'flex justify-center')}>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setCollapsed(!isCollapsed)}
            className="h-8 w-8"
          >
            {isCollapsed ? (
              <PanelLeft className="h-4 w-4" />
            ) : (
              <PanelLeftClose className="h-4 w-4" />
            )}
          </Button>
        </div>
      </div>
    </aside>
  );
}
