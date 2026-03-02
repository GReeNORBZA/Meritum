'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { type NavItem } from '@/config/navigation';
import { useAuthStore } from '@/stores/auth.store';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

interface SidebarNavProps {
  items: NavItem[];
  collapsed?: boolean;
}

export function SidebarNav({ items, collapsed }: SidebarNavProps) {
  const pathname = usePathname();
  const { hasPermission } = useAuthStore();

  return (
    <nav className="flex flex-col gap-1 px-2">
      {items.map((item) => {
        if (item.permission && !hasPermission(item.permission)) return null;

        const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
        const Icon = item.icon;

        if (item.children && !collapsed) {
          return (
            <Collapsible key={item.href} defaultOpen={isActive}>
              <CollapsibleTrigger className={cn(
                'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                isActive && 'bg-sidebar-accent text-sidebar-accent-foreground'
              )}>
                <Icon className="h-4 w-4 shrink-0" />
                <span className="flex-1 text-left">{item.title}</span>
                <ChevronRight className="h-4 w-4 shrink-0 transition-transform duration-200 [[data-state=open]>&]:rotate-90" />
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="ml-4 mt-1 flex flex-col gap-1 border-l pl-4">
                  {item.children.map((child) => {
                    if (child.permission && !hasPermission(child.permission)) return null;
                    const childActive = pathname === child.href;
                    return (
                      <Link
                        key={child.href}
                        href={child.href}
                        className={cn(
                          'flex items-center gap-3 rounded-lg px-3 py-1.5 text-sm transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                          childActive && 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
                        )}
                      >
                        {child.title}
                      </Link>
                    );
                  })}
                </div>
              </CollapsibleContent>
            </Collapsible>
          );
        }

        return (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
              isActive && 'bg-sidebar-accent text-sidebar-accent-foreground',
              collapsed && 'justify-center px-2'
            )}
            title={collapsed ? item.title : undefined}
          >
            <Icon className="h-4 w-4 shrink-0" />
            {!collapsed && <span>{item.title}</span>}
          </Link>
        );
      })}
    </nav>
  );
}
