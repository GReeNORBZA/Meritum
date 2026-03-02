import {
  LayoutDashboard,
  FileText,
  Users,
  Settings,
  BarChart3,
  Bell,
  HelpCircle,
  Shield,
  Layers,
  Briefcase,
  Smartphone,
  type LucideIcon,
} from 'lucide-react';
import { ROUTES } from '@/config/routes';

export interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
  permission?: string;
  children?: NavItem[];
  badge?: string;
}

export const mainNavItems: NavItem[] = [
  {
    title: 'Dashboard',
    href: ROUTES.DASHBOARD,
    icon: LayoutDashboard,
  },
  {
    title: 'Claims',
    href: ROUTES.CLAIMS,
    icon: FileText,
    permission: 'CLAIM_VIEW',
    children: [
      { title: 'All Claims', href: ROUTES.CLAIMS, icon: FileText },
      { title: 'New Claim', href: ROUTES.CLAIMS_NEW, icon: FileText, permission: 'CLAIM_CREATE' },
      { title: 'Templates', href: ROUTES.CLAIMS_TEMPLATES, icon: FileText },
      { title: 'Import', href: ROUTES.CLAIMS_IMPORT, icon: FileText, permission: 'CLAIM_CREATE' },
    ],
  },
  {
    title: 'WCB',
    href: ROUTES.WCB,
    icon: Briefcase,
    permission: 'CLAIM_VIEW',
    children: [
      { title: 'All WCB Claims', href: ROUTES.WCB, icon: Briefcase },
      { title: 'New WCB Claim', href: ROUTES.WCB_NEW, icon: Briefcase, permission: 'CLAIM_CREATE' },
    ],
  },
  {
    title: 'Patients',
    href: ROUTES.PATIENTS,
    icon: Users,
    permission: 'PATIENT_VIEW',
    children: [
      { title: 'All Patients', href: ROUTES.PATIENTS, icon: Users },
      { title: 'New Patient', href: ROUTES.PATIENTS_NEW, icon: Users, permission: 'PATIENT_CREATE' },
      { title: 'Import', href: ROUTES.PATIENTS_IMPORT, icon: Users, permission: 'PATIENT_CREATE' },
    ],
  },
  {
    title: 'Batches',
    href: ROUTES.BATCHES,
    icon: Layers,
    permission: 'CLAIM_VIEW',
  },
  {
    title: 'Analytics',
    href: ROUTES.ANALYTICS,
    icon: BarChart3,
    permission: 'ANALYTICS_VIEW',
    children: [
      { title: 'Dashboards', href: ROUTES.ANALYTICS, icon: BarChart3 },
      { title: 'Reports', href: ROUTES.REPORTS, icon: BarChart3 },
    ],
  },
];

export const bottomNavItems: NavItem[] = [
  {
    title: 'Settings',
    href: ROUTES.SETTINGS,
    icon: Settings,
  },
  {
    title: 'Support',
    href: ROUTES.SUPPORT,
    icon: HelpCircle,
  },
];

export const adminNavItems: NavItem[] = [
  {
    title: 'Admin',
    href: ROUTES.ADMIN_REFERENCE,
    icon: Shield,
    children: [
      { title: 'Reference Data', href: ROUTES.ADMIN_REFERENCE, icon: Shield },
      { title: 'Holidays', href: ROUTES.ADMIN_HOLIDAYS, icon: Shield },
      { title: 'AI Rules', href: ROUTES.ADMIN_RULES, icon: Shield },
      { title: 'Incidents', href: ROUTES.ADMIN_INCIDENTS, icon: Shield },
      { title: 'Components', href: ROUTES.ADMIN_COMPONENTS, icon: Shield },
      { title: 'Tickets', href: ROUTES.ADMIN_TICKETS, icon: Shield },
      { title: 'Notifications', href: ROUTES.ADMIN_NOTIFICATIONS, icon: Shield },
    ],
  },
];

export const mobileNavItems: NavItem[] = [
  {
    title: 'Mobile',
    href: ROUTES.MOBILE,
    icon: Smartphone,
    children: [
      { title: 'Shift', href: ROUTES.MOBILE_SHIFT, icon: Smartphone },
      { title: 'Quick Claim', href: ROUTES.MOBILE_CLAIM, icon: Smartphone },
      { title: 'Favourites', href: ROUTES.MOBILE_FAVOURITES, icon: Smartphone },
    ],
  },
];
