'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useSession } from '@/hooks/use-session';
import { useAuthStore } from '@/stores/auth.store';
import { ROUTES } from '@/config/routes';
import { Skeleton } from '@/components/ui/skeleton';

interface AuthGateProps {
  children: React.ReactNode;
  requiredRole?: 'physician' | 'delegate' | 'admin';
}

export function AuthGate({ children, requiredRole }: AuthGateProps) {
  const router = useRouter();
  const { isLoading } = useSession();
  const { user, isAuthenticated } = useAuthStore();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push(ROUTES.LOGIN);
    }
  }, [isLoading, isAuthenticated, router]);

  useEffect(() => {
    if (user && !user.onboardingComplete) {
      router.push('/onboarding');
    }
  }, [user, router]);

  useEffect(() => {
    if (requiredRole && user && user.role !== requiredRole && user.role !== 'admin') {
      router.push(ROUTES.DASHBOARD);
    }
  }, [requiredRole, user, router]);

  if (isLoading) {
    return (
      <div className="flex flex-col gap-4 p-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!isAuthenticated) return null;

  return <>{children}</>;
}
