'use client';

import * as React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatDateTime } from '@/lib/formatters/date';
import {
  Plus,
  Pencil,
  Brain,
  TrendingUp,
  Target,
  CheckCircle,
  Loader2,
  Search,
} from 'lucide-react';
import { useDebounce } from '@/hooks/use-debounce';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Types ----------

interface Rule {
  id: string;
  rule_id: string;
  type: 'validation' | 'suggestion' | 'bundling' | 'modifier' | 'rejection_prevention';
  description: string;
  condition: string;
  action: string;
  confidence: number;
  status: 'ACTIVE' | 'INACTIVE';
  acceptance_rate: number;
  times_triggered: number;
  times_accepted: number;
  created_at: string;
  updated_at: string;
}

interface RulesResponse {
  data: Rule[];
  pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
}

interface RuleFormData {
  type: Rule['type'];
  description: string;
  condition: string;
  action: string;
  confidence: number;
}

const RULE_TYPES = [
  { value: 'validation', label: 'Validation' },
  { value: 'suggestion', label: 'Suggestion' },
  { value: 'bundling', label: 'Bundling' },
  { value: 'modifier', label: 'Modifier' },
  { value: 'rejection_prevention', label: 'Rejection Prevention' },
] as const;

const EMPTY_FORM: RuleFormData = {
  type: 'validation',
  description: '',
  condition: '',
  action: '',
  confidence: 0.8,
};

// ---------- Main Page ----------

export default function AdminRulesPage() {
  const queryClient = useQueryClient();

  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [searchInput, setSearchInput] = React.useState('');
  const [typeFilter, setTypeFilter] = React.useState('');
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editingRule, setEditingRule] = React.useState<Rule | null>(null);
  const [formData, setFormData] = React.useState<RuleFormData>(EMPTY_FORM);

  const search = useDebounce(searchInput, 300);

  const filters = {
    search: search || undefined,
    type: typeFilter || undefined,
    page,
    pageSize,
  };

  const { data, isLoading } = useQuery({
    queryKey: [...queryKeys.intelligence.rules(filters)],
    queryFn: () =>
      api.get<RulesResponse>('/api/v1/admin/rules', { params: filters }),
  });

  const createMutation = useMutation({
    mutationFn: (payload: RuleFormData) =>
      api.post('/api/v1/admin/rules', payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.all });
      closeDialog();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, ...payload }: RuleFormData & { id: string }) =>
      api.put(`/api/v1/admin/rules/${id}`, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.all });
      closeDialog();
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'ACTIVE' | 'INACTIVE' }) =>
      api.patch(`/api/v1/admin/rules/${id}`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.all });
    },
  });

  const openCreate = () => {
    setEditingRule(null);
    setFormData(EMPTY_FORM);
    setDialogOpen(true);
  };

  const openEdit = (rule: Rule) => {
    setEditingRule(rule);
    setFormData({
      type: rule.type,
      description: rule.description,
      condition: rule.condition,
      action: rule.action,
      confidence: rule.confidence,
    });
    setDialogOpen(true);
  };

  const closeDialog = () => {
    setDialogOpen(false);
    setEditingRule(null);
    setFormData(EMPTY_FORM);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, ...formData });
    } else {
      createMutation.mutate(formData);
    }
  };

  const isSaving = createMutation.isPending || updateMutation.isPending;

  // ---------- Stats ----------

  const rules = data?.data ?? [];
  const totalRules = data?.pagination?.total ?? 0;
  const activeRules = rules.filter((r) => r.status === 'ACTIVE').length;
  const avgAcceptance =
    rules.length > 0
      ? rules.reduce((sum, r) => sum + r.acceptance_rate, 0) / rules.length
      : 0;
  const totalTriggered = rules.reduce((sum, r) => sum + r.times_triggered, 0);

  // ---------- Columns ----------

  const columns: ColumnDef<Rule>[] = [
    {
      accessorKey: 'rule_id',
      header: 'Rule ID',
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.rule_id}</span>
      ),
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: ({ row }) => (
        <Badge variant="outline" className="capitalize">
          {row.original.type.replace(/_/g, ' ')}
        </Badge>
      ),
    },
    {
      accessorKey: 'description',
      header: 'Description',
      cell: ({ row }) => (
        <span className="text-sm line-clamp-2">{row.original.description}</span>
      ),
    },
    {
      accessorKey: 'confidence',
      header: 'Confidence',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <div className="h-2 w-16 rounded-full bg-secondary">
            <div
              className="h-2 rounded-full bg-primary"
              style={{ width: `${row.original.confidence * 100}%` }}
            />
          </div>
          <span className="text-xs text-muted-foreground">
            {Math.round(row.original.confidence * 100)}%
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Switch
            checked={row.original.status === 'ACTIVE'}
            onCheckedChange={(checked) =>
              toggleMutation.mutate({
                id: row.original.id,
                status: checked ? 'ACTIVE' : 'INACTIVE',
              })
            }
            disabled={toggleMutation.isPending}
          />
          <StatusBadge status={row.original.status} />
        </div>
      ),
    },
    {
      id: 'acceptance_rate',
      header: 'Acceptance Rate',
      cell: ({ row }) => (
        <div className="text-sm">
          <span className="font-medium">
            {Math.round(row.original.acceptance_rate * 100)}%
          </span>
          <span className="text-xs text-muted-foreground ml-1">
            ({row.original.times_accepted}/{row.original.times_triggered})
          </span>
        </div>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => openEdit(row.original)}
          >
            <Pencil className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">AI Rules</h1>
          <p className="text-muted-foreground">
            Manage validation rules, suggestions, and AI-powered billing intelligence
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          Create Rule
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
            <Brain className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalRules}</div>
            <p className="text-xs text-muted-foreground">{activeRules} active</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Avg Acceptance</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {Math.round(avgAcceptance * 100)}%
            </div>
            <p className="text-xs text-muted-foreground">Across all rules</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Times Triggered</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {totalTriggered.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">Total evaluations</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{activeRules}</div>
            <p className="text-xs text-muted-foreground">
              {totalRules > 0
                ? `${Math.round((activeRules / totalRules) * 100)}% of total`
                : 'No rules yet'}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Search + Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search rules..."
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>
        <Select
          value={typeFilter}
          onValueChange={(val) => {
            setTypeFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="All Types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="">All Types</SelectItem>
            {RULE_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value}>
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Data Table */}
      <DataTable
        columns={columns}
        data={rules}
        isLoading={isLoading}
        pagination={{
          page,
          pageSize,
          total: data?.pagination?.total ?? 0,
        }}
        onPaginationChange={(newPage, newPageSize) => {
          setPage(newPage);
          setPageSize(newPageSize);
        }}
      />

      {/* Create/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingRule ? 'Edit Rule' : 'Create Rule'}
            </DialogTitle>
            <DialogDescription>
              {editingRule
                ? 'Update rule configuration and parameters.'
                : 'Define a new AI rule for billing intelligence.'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="rule-type">Type</Label>
              <Select
                value={formData.type}
                onValueChange={(val) =>
                  setFormData((prev) => ({ ...prev, type: val as Rule['type'] }))
                }
              >
                <SelectTrigger id="rule-type">
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  {RULE_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="rule-description">Description</Label>
              <Textarea
                id="rule-description"
                value={formData.description}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, description: e.target.value }))
                }
                placeholder="Describe what this rule does..."
                rows={3}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="rule-condition">Condition</Label>
              <Textarea
                id="rule-condition"
                value={formData.condition}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, condition: e.target.value }))
                }
                placeholder="When should this rule trigger..."
                rows={2}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="rule-action">Action</Label>
              <Textarea
                id="rule-action"
                value={formData.action}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, action: e.target.value }))
                }
                placeholder="What action should be taken..."
                rows={2}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="rule-confidence">
                Confidence Threshold ({Math.round(formData.confidence * 100)}%)
              </Label>
              <Input
                id="rule-confidence"
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={formData.confidence}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    confidence: parseFloat(e.target.value),
                  }))
                }
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={closeDialog}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSaving}>
                {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingRule ? 'Save Changes' : 'Create Rule'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
