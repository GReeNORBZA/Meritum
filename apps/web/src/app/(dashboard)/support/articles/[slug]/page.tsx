'use client';

import * as React from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useArticle } from '@/hooks/api/use-support';
import { ROUTES } from '@/config/routes';
import { ArticleFeedback } from '@/components/domain/support/article-feedback';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ChevronRight, FileText, Clock, ArrowLeft } from 'lucide-react';
import { formatDate } from '@/lib/formatters/date';

export default function ArticleDetailPage() {
  const params = useParams<{ slug: string }>();
  const slug = params.slug;

  const { data, isLoading } = useArticle(slug);
  const article = data?.data;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-4 w-48" />
        <Skeleton className="h-8 w-3/4" />
        <Skeleton className="h-4 w-32" />
        <div className="space-y-3 mt-6">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-4/5" />
        </div>
      </div>
    );
  }

  if (!article) {
    return (
      <div className="space-y-4">
        <Link
          href={ROUTES.SUPPORT}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Help Centre
        </Link>
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">Article not found.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-1.5 text-sm text-muted-foreground">
        <Link href={ROUTES.SUPPORT} className="hover:text-foreground transition-colors">
          Help Centre
        </Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="capitalize">{article.category.replace(/-/g, ' ')}</span>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="text-foreground truncate max-w-[200px]">{article.title}</span>
      </nav>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_300px]">
        {/* Main Content */}
        <div className="space-y-6">
          {/* Article Header */}
          <div>
            <h1 className="text-2xl font-bold tracking-tight">{article.title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
              <div className="flex items-center gap-1">
                <Clock className="h-3.5 w-3.5" />
                <span>Updated {formatDate(article.updated_at)}</span>
              </div>
              {article.tags.length > 0 && (
                <div className="flex items-center gap-1.5">
                  {article.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>

          <Separator />

          {/* Article Body */}
          <div
            className="prose prose-sm max-w-none dark:prose-invert prose-headings:font-semibold prose-a:text-primary prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5"
            dangerouslySetInnerHTML={{ __html: article.content }}
          />

          <Separator />

          {/* Feedback Widget */}
          <ArticleFeedback slug={slug} />
        </div>

        {/* Sidebar - Related Articles */}
        <aside className="space-y-4">
          {article.related_articles && article.related_articles.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Related Articles</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {article.related_articles.map((related) => (
                  <Link
                    key={related.slug}
                    href={ROUTES.SUPPORT_ARTICLE(related.slug)}
                    className="flex items-start gap-2 rounded-md p-2 -mx-2 hover:bg-accent transition-colors"
                  >
                    <FileText className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                    <div className="min-w-0">
                      <p className="text-sm font-medium leading-tight">{related.title}</p>
                      <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
                        {related.summary}
                      </p>
                    </div>
                  </Link>
                ))}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Need More Help?</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p className="text-muted-foreground">
                Can&apos;t find the answer you need?
              </p>
              <Link
                href={ROUTES.SUPPORT_TICKET_NEW}
                className="inline-flex items-center gap-1 text-primary hover:underline"
              >
                Submit a support ticket
                <ChevronRight className="h-3.5 w-3.5" />
              </Link>
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}
