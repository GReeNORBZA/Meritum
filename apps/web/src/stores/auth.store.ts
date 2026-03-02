import { create } from 'zustand';

interface DelegateContext {
  delegateUserId: string;
  physicianProviderId: string;
  physicianName: string;
  permissions: string[];
}

interface User {
  userId: string;
  email: string;
  fullName: string;
  role: 'physician' | 'delegate' | 'admin';
  providerId: string | null;
  mfaEnabled: boolean;
  onboardingComplete: boolean;
  subscriptionStatus: string;
}

interface AuthState {
  user: User | null;
  delegateContext: DelegateContext | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  setUser: (user: User | null) => void;
  setDelegateContext: (ctx: DelegateContext | null) => void;
  setLoading: (loading: boolean) => void;
  logout: () => void;
  hasPermission: (permission: string) => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  delegateContext: null,
  isAuthenticated: false,
  isLoading: true,
  setUser: (user) => set({ user, isAuthenticated: !!user, isLoading: false }),
  setDelegateContext: (delegateContext) => set({ delegateContext }),
  setLoading: (isLoading) => set({ isLoading }),
  logout: () => set({ user: null, delegateContext: null, isAuthenticated: false }),
  hasPermission: (permission) => {
    const { user, delegateContext } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    if (user.role === 'physician') return true;
    if (delegateContext) {
      return delegateContext.permissions.includes(permission);
    }
    return false;
  },
}));
