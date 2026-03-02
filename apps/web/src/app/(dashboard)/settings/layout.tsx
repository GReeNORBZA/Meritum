'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ROUTES } from '@/config/routes';
import { cn } from '@/lib/utils';

const settingsNav = [
  { href: ROUTES.SETTINGS_PROFILE, label: 'Profile' },
  { href: ROUTES.SETTINGS_BA, label: 'Business Arrangements' },
  { href: ROUTES.SETTINGS_LOCATIONS, label: 'Locations' },
  { href: ROUTES.SETTINGS_WCB, label: 'WCB Configuration' },
  { href: ROUTES.SETTINGS_SUBMISSION, label: 'Submission Preferences' },
  { href: ROUTES.SETTINGS_ROUTING, label: 'Smart Routing' },
  { href: ROUTES.SETTINGS_DELEGATES, label: 'Delegates' },
  { href: ROUTES.SETTINGS_NOTIFICATIONS, label: 'Notifications' },
  { href: ROUTES.SETTINGS_AI_COACH, label: 'AI Coach' },
  { href: ROUTES.SETTINGS_SUBSCRIPTION, label: 'Subscription' },
  { href: ROUTES.SETTINGS_EXPORT, label: 'Data Export' },
  { href: ROUTES.SETTINGS_SECURITY, label: 'Security' },
];

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">Manage your account and practice settings</p>
      </div>
      <div className="flex flex-col gap-6 md:flex-row">
        <nav className="w-full md:w-56 shrink-0">
          <div className="flex flex-col gap-1">
            {settingsNav.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent',
                  pathname === item.href ? 'bg-accent font-medium' : 'text-muted-foreground'
                )}
              >
                {item.label}
              </Link>
            ))}
          </div>
        </nav>
        <div className="flex-1 min-w-0">{children}</div>
      </div>
    </div>
  );
}
