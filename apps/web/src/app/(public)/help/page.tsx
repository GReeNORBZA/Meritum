'use client';

import * as React from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { useArticleSearch, type Article, type ArticleSummary } from '@/hooks/api/use-support';
import { useDebounce } from '@/hooks/use-debounce';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import type { PaginatedResponse } from '@/lib/api/client';
import {
  BookOpen,
  CreditCard,
  FileCheck,
  HardHat,
  BarChart3,
  UserCog,
  Search,
  FileText,
  ChevronRight,
  X,
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

export default function PublicHelpPage() {
  const [searchQuery, setSearchQuery] = React.useState('');
  const [selectedCategory, setSelectedCategory] = React.useState<string | undefined>(undefined);
  const debouncedSearch = useDebounce(searchQuery, 300);

  // Fetch articles
  const { data: articlesData, isLoading: articlesLoading } = useQuery({
    queryKey: ['public', 'help', 'articles', selectedCategory],
    queryFn: () =>
      api.get<PaginatedResponse<Article>>('/api/v1/help/articles', {
        params: {
          category: selectedCategory,
          page_size: 10,
        },
      }),
  });

  // Search articles
  const { data: searchData, isLoading: searchLoading } = useArticleSearch(debouncedSearch);

  const articles = articlesData?.data ?? [];
  const searchResults = searchData?.data ?? [];
  const isSearching = debouncedSearch.length >= 2;

  const clearSearch = () => {
    setSearchQuery('');
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto max-w-4xl px-4 py-12">
        {/* Header */}
        <div className="text-center mb-10">
          <h1 className="text-3xl font-bold tracking-tight mb-2">Help Centre</h1>
          <p className="text-muted-foreground text-lg">
            Find answers to your questions about Meritum
          </p>
        </div>

        {/* Search Bar */}
        <div className="relative max-w-xl mx-auto mb-10">
          <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search help articles..."
            className="pl-11 pr-10 h-12 text-base"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={clearSearch}
              className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        {/* Search Results */}
        {isSearching ? (
          <div className="mb-10">
            <h2 className="text-lg font-semibold mb-4">
              Search Results for &quot;{debouncedSearch}&quot;
            </h2>
            {searchLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-lg border p-4">
                    <Skeleton className="h-5 w-5 shrink-0" />
                    <div className="flex-1 space-y-1">
                      <Skeleton className="h-4 w-3/4" />
                      <Skeleton className="h-3 w-full" />
                    </div>
                  </div>
                ))}
              </div>
            ) : searchResults.length > 0 ? (
              <div className="space-y-2">
                {searchResults.map((article: ArticleSummary) => (
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
                      <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                        {article.summary}
                      </p>
                    </div>
                    <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                  </Link>
                ))}
              </div>
            ) : (
              <Card>
                <CardContent className="py-8 text-center text-sm text-muted-foreground">
                  No articles found matching your search.
                </CardContent>
              </Card>
            )}
          </div>
        ) : (
          <>
            {/* Category Cards */}
            <div className="mb-10">
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

              {articlesLoading ? (
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
                        <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                          {article.summary}
                        </p>
                      </div>
                      <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
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
          </>
        )}

        {/* Footer */}
        <div className="mt-10 text-center text-sm text-muted-foreground">
          <p>
            Need more help?{' '}
            <Link href={ROUTES.LOGIN} className="text-primary hover:underline">
              Sign in
            </Link>{' '}
            to submit a support ticket.
          </p>
        </div>
      </div>
    </div>
  );
}
