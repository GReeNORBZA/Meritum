'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { PaginatedResponse, ApiResponse } from '@/lib/api/client';

// ---------- Types ----------

export interface ArticleCategory {
  slug: string;
  name: string;
  description: string;
  icon: string;
  article_count: number;
}

export interface Article {
  id: string;
  slug: string;
  title: string;
  summary: string;
  content: string;
  category: string;
  tags: string[];
  helpful_count: number;
  not_helpful_count: number;
  related_articles?: ArticleSummary[];
  created_at: string;
  updated_at: string;
}

export interface ArticleSummary {
  slug: string;
  title: string;
  summary: string;
  category: string;
}

export interface ArticleFilters {
  category?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

export interface ArticleFeedbackInput {
  slug: string;
  helpful: boolean;
  comment?: string;
}

export interface Ticket {
  id: string;
  ticket_number: string;
  subject: string;
  category: 'billing' | 'technical' | 'claims' | 'account' | 'other';
  status: 'OPEN' | 'PENDING' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED';
  description: string;
  context?: {
    page_url?: string;
    browser_info?: string;
  };
  messages: TicketMessage[];
  rating?: TicketRating | null;
  created_at: string;
  updated_at: string;
}

export interface TicketMessage {
  id: string;
  sender_type: 'user' | 'support';
  sender_name: string;
  content: string;
  attachments?: { name: string; url: string }[];
  created_at: string;
}

export interface TicketRating {
  score: number;
  comment?: string;
  created_at: string;
}

export interface TicketFilters {
  status?: string;
  page?: number;
  pageSize?: number;
}

export interface CreateTicketInput {
  subject: string;
  category: 'billing' | 'technical' | 'claims' | 'account' | 'other';
  description: string;
  attachments?: File[];
  context?: {
    page_url?: string;
    browser_info?: string;
  };
}

export interface ReplyToTicketInput {
  id: string;
  content: string;
  attachments?: File[];
}

export interface SubmitRatingInput {
  id: string;
  score: number;
  comment?: string;
}

// ---------- Article Queries ----------

export function useArticles(filters: ArticleFilters = {}) {
  const { category, search, page = 1, pageSize = 20 } = filters;

  return useQuery({
    queryKey: queryKeys.support.articles({ category, search, page, pageSize }),
    queryFn: () =>
      api.get<PaginatedResponse<Article>>('/api/v1/help/articles', {
        params: {
          category,
          search,
          page,
          page_size: pageSize,
        },
      }),
  });
}

export function useArticle(slug: string) {
  return useQuery({
    queryKey: queryKeys.support.article(slug),
    queryFn: () => api.get<ApiResponse<Article>>(`/api/v1/help/articles/${slug}`),
    enabled: !!slug,
  });
}

export function useArticleSearch(query: string) {
  return useQuery({
    queryKey: [...queryKeys.support.all, 'search', query],
    queryFn: () =>
      api.get<ApiResponse<ArticleSummary[]>>('/api/v1/help/articles', {
        params: { search: query },
      }),
    enabled: query.length >= 2,
  });
}

// ---------- Feedback Mutation ----------

export function useSubmitFeedback() {
  return useMutation({
    mutationFn: ({ slug, helpful, comment }: ArticleFeedbackInput) =>
      api.post<ApiResponse<{ success: boolean }>>(
        `/api/v1/help/articles/${slug}/feedback`,
        { helpful, comment }
      ),
  });
}

// ---------- Ticket Queries ----------

export function useTickets(filters: TicketFilters = {}) {
  const { status, page = 1, pageSize = 20 } = filters;

  return useQuery({
    queryKey: queryKeys.support.tickets({ status, page, pageSize }),
    queryFn: () =>
      api.get<PaginatedResponse<Ticket>>('/api/v1/support/tickets', {
        params: {
          status,
          page,
          page_size: pageSize,
        },
      }),
  });
}

export function useTicket(id: string) {
  return useQuery({
    queryKey: queryKeys.support.ticket(id),
    queryFn: () => api.get<ApiResponse<Ticket>>(`/api/v1/support/tickets/${id}`),
    enabled: !!id,
  });
}

// ---------- Ticket Mutations ----------

export function useCreateTicket() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateTicketInput) => {
      const formData = new FormData();
      formData.append('subject', data.subject);
      formData.append('category', data.category);
      formData.append('description', data.description);
      if (data.context) {
        formData.append('context', JSON.stringify(data.context));
      }
      if (data.attachments) {
        data.attachments.forEach((file) => {
          formData.append('attachments', file);
        });
      }
      return api.post<ApiResponse<Ticket>>('/api/v1/support/tickets', formData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.support.all });
    },
  });
}

export function useReplyToTicket() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, content, attachments }: ReplyToTicketInput) => {
      const formData = new FormData();
      formData.append('content', content);
      if (attachments) {
        attachments.forEach((file) => {
          formData.append('attachments', file);
        });
      }
      return api.post<ApiResponse<TicketMessage>>(
        `/api/v1/support/tickets/${id}/replies`,
        formData
      );
    },
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.support.ticket(variables.id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.support.tickets() });
    },
  });
}

export function useSubmitRating() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, score, comment }: SubmitRatingInput) =>
      api.post<ApiResponse<TicketRating>>(
        `/api/v1/support/tickets/${id}/rating`,
        { score, comment }
      ),
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.support.ticket(variables.id) });
    },
  });
}
