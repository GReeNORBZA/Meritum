'use client';

import { Sidebar } from '@/components/layout/sidebar';
import { Header } from '@/components/layout/header';
import { SubscriptionBanner } from '@/components/layout/subscription-banner';
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet';
import { useSidebarStore } from '@/stores/sidebar.store';
import { SidebarNav } from '@/components/layout/sidebar-nav';
import { mainNavItems, bottomNavItems } from '@/config/navigation';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { isOpen, setOpen } = useSidebarStore();

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />

      {/* Mobile sidebar */}
      <Sheet open={isOpen} onOpenChange={setOpen}>
        <SheetContent side="left" className="w-64 p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <div className="flex h-14 items-center border-b px-4">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold text-sm">
                M
              </div>
              <span className="text-lg font-semibold">Meritum</span>
            </div>
          </div>
          <ScrollArea className="flex-1 py-4">
            <SidebarNav items={mainNavItems} />
            <Separator className="my-4 mx-2" />
            <SidebarNav items={bottomNavItems} />
          </ScrollArea>
        </SheetContent>
      </Sheet>

      <div className="flex flex-1 flex-col overflow-hidden">
        <SubscriptionBanner />
        <Header />
        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
