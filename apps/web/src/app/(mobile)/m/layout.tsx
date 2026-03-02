'use client';

import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { ROUTES } from '@/config/routes';
import { cn } from '@/lib/utils';
import { Home, Clock, FileText, Star } from 'lucide-react';

const tabs = [
  { href: ROUTES.MOBILE, label: 'Home', icon: Home },
  { href: ROUTES.MOBILE_SHIFT, label: 'Shift', icon: Clock },
  { href: ROUTES.MOBILE_CLAIM, label: 'Claim', icon: FileText },
  { href: ROUTES.MOBILE_FAVOURITES, label: 'Favourites', icon: Star },
];

export default function MobileLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen pb-16">
      <main className="p-4">{children}</main>
      <nav className="fixed bottom-0 left-0 right-0 border-t bg-background z-50">
        <div className="flex items-center justify-around h-16">
          {tabs.map(({ href, label, icon: Icon }) => {
            const isActive = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  'flex flex-col items-center gap-1 px-3 py-2 text-xs',
                  isActive ? 'text-primary' : 'text-muted-foreground'
                )}
              >
                <Icon className="h-5 w-5" />
                <span>{label}</span>
              </Link>
            );
          })}
        </div>
      </nav>
    </div>
  );
}
