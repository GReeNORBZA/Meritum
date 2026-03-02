import type { Metadata } from 'next';
import { QueryProvider } from '@/providers/query-provider';
import { ToastProvider } from '@/providers/toast-provider';
import '@/app/globals.css';

export const metadata: Metadata = {
  title: 'Meritum',
  description: 'Self-serve billing platform for Alberta physicians',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <QueryProvider>
          {children}
          <ToastProvider />
        </QueryProvider>
      </body>
    </html>
  );
}
