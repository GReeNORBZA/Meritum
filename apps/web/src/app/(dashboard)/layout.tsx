import { DashboardLayout } from '@/components/layout/dashboard-layout';
import { AuthGate } from '@/components/auth/auth-gate';

export default function DashboardGroupLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthGate>
      <DashboardLayout>{children}</DashboardLayout>
    </AuthGate>
  );
}
