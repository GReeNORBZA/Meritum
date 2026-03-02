'use client';

import * as React from 'react';
import Link from 'next/link';
import { useArticles } from '@/hooks/api/use-support';
import { ROUTES } from '@/config/routes';
import { HelpSearch } from '@/components/domain/support/help-search';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import {
  BookOpen,
  CreditCard,
  FileCheck,
  HardHat,
  BarChart3,
  UserCog,
  FileText,
  Ticket,
  ChevronRight,
} from 'lucide-react';

// ---------- Category Definitions ----------

const CATEGORIES = [
  {
    slug: 'getting-started',
    name: 'Getting Started',
    description: 'Learn the basics of setting up and using the platform',
    icon: BookOpen,
  },
  {
    slug: 'billing',
    name: 'Billing',
    description: 'Subscription plans, invoices, and payment questions',
    icon: CreditCard,
  },
  {
    slug: 'claims',
    name: 'Claims',
    description: 'AHCIP claim submission, validation, and tracking',
    icon: FileCheck,
  },
  {
    slug: 'wcb',
    name: 'WCB',
    description: 'Workers\' Compensation Board forms and processes',
    icon: HardHat,
  },
  {
    slug: 'analytics',
    name: 'Analytics',
    description: 'Reports, dashboards, and revenue analytics',
    icon: BarChart3,
  },
  {
    slug: 'account',
    name: 'Account',
    description: 'Profile settings, security, and team management',
    icon: UserCog,
  },
] as const;

// ---------- Main Page ----------

export default function SupportPage() {
  const [selectedCategory, setSelectedCategory] = React.useState<string | undefined>(undefined);

  const { data, isLoading } = useArticles({
    category: selectedCategory,
    pageSize: 10,
  });

  const articles = data?.data ?? [];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Help Centre</h1>
          <p className="text-muted-foreground">
            Find answers and get support for your questions
          </p>
        </div>
        <Link href={ROUTES.SUPPORT_TICKET_NEW}>
          <Button>
            <Ticket className="mr-2 h-4 w-4" />
            Submit a Ticket
          </Button>
        </Link>
      </div>

      {/* Search */}
      <HelpSearch className="max-w-xl" placeholder="Search for help articles..." />

      {/* Category Cards */}
      <div>
        <h2 className="text-lg font-semibold mb-4">Browse by Category</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {CATEGORIES.map((category) => {
            const Icon = category.icon;
            const isActive = selectedCategory === category.slug;
            return (
              <Card
                key={category.slug}
                className={`cursor-pointer transition-colors hover:border-primary/50 ${
                  isActive ? 'border-primary bg-primary/5' : ''
                }`}
                onClick={() =>
                  setSelectedCategory(isActive ? undefined : category.slug)
                }
              >
                <CardHeader className="pb-3">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <CardTitle className="text-base">{category.name}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription>{category.description}</CardDescription>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Popular / Filtered Articles */}
      <div>
        <h2 className="text-lg font-semibold mb-4">
          {selectedCategory
            ? `${CATEGORIES.find((c) => c.slug === selectedCategory)?.name ?? ''} Articles`
            : 'Popular Articles'}
        </h2>

        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg border p-4">
                <Skeleton className="h-5 w-5 shrink-0" />
                <div className="flex-1 space-y-1">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-full" />
                </div>
              </div>
            ))}
          </div>
        ) : articles.length > 0 ? (
          <div className="space-y-2">
            {articles.map((article) => (
              <Link
                key={article.slug}
                href={ROUTES.SUPPORT_ARTICLE(article.slug)}
                className="flex items-center gap-3 rounded-lg border p-4 hover:bg-accent transition-colors group"
              >
                <FileText className="h-5 w-5 shrink-0 text-muted-foreground" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium group-hover:text-primary transition-colors">
                    {article.title}
                  </p>
                  <p className="text-xs text-muted-foreground line-clamp-1 mt-0.5">
                    {article.summary}
                  </p>
                </div>
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground group-hover:text-primary transition-colors" />
              </Link>
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="py-8 text-center text-sm text-muted-foreground">
              No articles found. Try selecting a different category.
            </CardContent>
          </Card>
        )}
      </div>

      {/* Quick Links */}
      <div className="flex items-center gap-4 rounded-lg border bg-muted/50 p-4">
        <p className="text-sm text-muted-foreground">
          Can&apos;t find what you&apos;re looking for?
        </p>
        <Link href={ROUTES.SUPPORT_TICKETS}>
          <Button variant="outline" size="sm">
            View My Tickets
          </Button>
        </Link>
        <Link href={ROUTES.SUPPORT_TICKET_NEW}>
          <Button size="sm">Contact Support</Button>
        </Link>
      </div>
    </div>
  );
}
