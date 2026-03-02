'use client';

import { useAuthStore } from '@/stores/auth.store';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ShieldX } from 'lucide-react';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const { user } = useAuthStore();

  if (user?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader className="text-center">
            <ShieldX className="mx-auto h-12 w-12 text-destructive mb-2" />
            <CardTitle>Access Denied</CardTitle>
          </CardHeader>
          <CardContent className="text-center text-muted-foreground">
            You don&apos;t have permission to access admin pages.
          </CardContent>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}
