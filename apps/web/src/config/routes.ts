export const ROUTES = {
  // Auth
  LOGIN: '/login',
  REGISTER: '/register',
  VERIFY_EMAIL: '/verify-email',
  MFA_SETUP: '/mfa-setup',
  FORGOT_PASSWORD: '/forgot-password',
  RESET_PASSWORD: '/reset-password',
  DELEGATE_ACCEPT: '/delegates/accept',
  // Dashboard
  DASHBOARD: '/',
  // Claims
  CLAIMS: '/claims',
  CLAIMS_NEW: '/claims/new',
  CLAIM_DETAIL: (id: string) => `/claims/${id}` as const,
  CLAIMS_TEMPLATES: '/claims/templates',
  CLAIMS_IMPORT: '/claims/import',
  // WCB
  WCB: '/wcb',
  WCB_NEW: '/wcb/new',
  WCB_DETAIL: (id: string) => `/wcb/${id}` as const,
  // Patients
  PATIENTS: '/patients',
  PATIENTS_NEW: '/patients/new',
  PATIENT_DETAIL: (id: string) => `/patients/${id}` as const,
  PATIENT_EDIT: (id: string) => `/patients/${id}/edit` as const,
  PATIENTS_IMPORT: '/patients/import',
  // Batches
  BATCHES: '/batches',
  BATCH_DETAIL: (id: string) => `/batches/${id}` as const,
  // Analytics
  ANALYTICS: '/analytics',
  REPORTS: '/reports',
  // Shifts
  SHIFTS: '/shifts',
  // Settings
  SETTINGS: '/settings',
  SETTINGS_PROFILE: '/settings/profile',
  SETTINGS_BA: '/settings/business-arrangements',
  SETTINGS_LOCATIONS: '/settings/locations',
  SETTINGS_WCB: '/settings/wcb-config',
  SETTINGS_SUBMISSION: '/settings/submission-preferences',
  SETTINGS_ROUTING: '/settings/routing',
  SETTINGS_DELEGATES: '/settings/delegates',
  SETTINGS_NOTIFICATIONS: '/settings/notifications',
  SETTINGS_AI_COACH: '/settings/ai-coach',
  SETTINGS_SUBSCRIPTION: '/settings/subscription',
  SETTINGS_EXPORT: '/settings/export',
  SETTINGS_PRACTICE: '/settings/practice',
  SETTINGS_REFERRAL: '/settings/referral',
  SETTINGS_SECURITY: '/settings/security',
  // Support
  SUPPORT: '/support',
  SUPPORT_TICKETS: '/support/tickets',
  SUPPORT_TICKET_NEW: '/support/tickets/new',
  SUPPORT_TICKET_DETAIL: (id: string) => `/support/tickets/${id}` as const,
  SUPPORT_ARTICLE: (slug: string) => `/support/articles/${slug}` as const,
  // Admin
  ADMIN_REFERENCE: '/admin/reference',
  ADMIN_HOLIDAYS: '/admin/reference/holidays',
  ADMIN_RULES: '/admin/rules',
  ADMIN_INCIDENTS: '/admin/incidents',
  ADMIN_COMPONENTS: '/admin/components',
  ADMIN_TICKETS: '/admin/tickets',
  ADMIN_NOTIFICATIONS: '/admin/notifications',
  // Mobile
  MOBILE: '/m',
  MOBILE_SHIFT: '/m/shift',
  MOBILE_CLAIM: '/m/claim',
  MOBILE_FAVOURITES: '/m/favourites',
  MOBILE_SCHEDULE: '/m/shift/schedule',
  // Public
  STATUS: '/status',
  HELP: '/help',
} as const;
