import type { Metadata } from 'next';

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
      <body>{children}</body>
    </html>
  );
}
