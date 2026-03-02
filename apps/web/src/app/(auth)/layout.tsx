export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background px-4">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center space-y-2 text-center">
          <h1 className="text-2xl font-bold">Meritum</h1>
          <p className="text-sm text-muted-foreground">Medical billing for Alberta physicians</p>
        </div>
        {children}
      </div>
    </div>
  );
}
