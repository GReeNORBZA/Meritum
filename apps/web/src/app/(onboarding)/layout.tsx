export default function OnboardingLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b px-6 py-4">
        <h1 className="text-xl font-bold">Meritum</h1>
      </header>
      <main className="container mx-auto max-w-3xl px-4 py-8">
        {children}
      </main>
    </div>
  );
}
