'use client';

import * as React from 'react';
import { useForm } from 'react-hook-form';
import {
  useClaimTemplates,
  useCreateTemplate,
  useDeleteTemplate,
  type ClaimTemplate,
} from '@/hooks/api/use-claims';
import { DataTable } from '@/components/data-table/data-table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
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
import { formatDate, formatRelative } from '@/lib/formatters/date';
import { Plus, Trash2, Copy, FileText, Loader2 } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Types ----------

interface CreateTemplateFormValues {
  name: string;
  description: string;
  claim_type: 'AHCIP' | 'WCB';
  hsc_code: string;
  calls: number;
}

// ---------- Columns ----------

function getColumns(
  onDelete: (id: string) => void,
  isDeleting: boolean
): ColumnDef<ClaimTemplate>[] {
  return [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <div>
          <span className="text-sm font-medium">{row.original.name}</span>
          {row.original.template_type === 'SPECIALTY_STARTER' && (
            <Badge variant="secondary" className="ml-2 text-xs">
              Starter
            </Badge>
          )}
        </div>
      ),
    },
    {
      id: 'hsc_code',
      header: 'HSC Code',
      cell: ({ row }) => (
        <div className="flex flex-wrap gap-1">
          {row.original.line_items.map((item) => (
            <Badge
              key={item.health_service_code}
              variant="outline"
              className="font-mono text-xs"
            >
              {item.health_service_code}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      accessorKey: 'description',
      header: 'Description',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground line-clamp-1">
          {row.original.description || '--'}
        </span>
      ),
    },
    {
      id: 'last_used',
      header: 'Last Used',
      cell: ({ row }) =>
        row.original.last_used_at ? (
          <span className="text-sm text-muted-foreground">
            {formatRelative(row.original.last_used_at)}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">Never</span>
        ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button variant="ghost" size="sm" title="Duplicate">
            <Copy className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            title="Delete"
            onClick={() => onDelete(row.original.id)}
            disabled={isDeleting}
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];
}

// ---------- Main Page ----------

export default function ClaimTemplatesPage() {
  const { data, isLoading } = useClaimTemplates();
  const createTemplate = useCreateTemplate();
  const deleteTemplate = useDeleteTemplate();

  const [showCreate, setShowCreate] = React.useState(false);
  const [deleteId, setDeleteId] = React.useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
    formState: { errors },
  } = useForm<CreateTemplateFormValues>({
    defaultValues: {
      name: '',
      description: '',
      claim_type: 'AHCIP',
      hsc_code: '',
      calls: 1,
    },
  });

  const onCreateSubmit = async (formData: CreateTemplateFormValues) => {
    await createTemplate.mutateAsync({
      name: formData.name,
      description: formData.description || undefined,
      claim_type: formData.claim_type,
      line_items: [
        {
          health_service_code: formData.hsc_code,
          calls: formData.calls,
        },
      ],
    });
    reset();
    setShowCreate(false);
  };

  const handleDelete = async (id: string) => {
    setDeleteId(id);
    await deleteTemplate.mutateAsync(id);
    setDeleteId(null);
  };

  const columns = React.useMemo(
    () => getColumns(handleDelete, deleteTemplate.isPending),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [deleteTemplate.isPending]
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Claim Templates</h1>
          <p className="text-muted-foreground">
            Save and reuse common claim configurations
          </p>
        </div>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Template
        </Button>
      </div>

      {/* Data Table */}
      <DataTable
        columns={columns}
        data={data?.data ?? []}
        isLoading={isLoading}
      />

      {/* Create Template Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Create Claim Template
            </DialogTitle>
            <DialogDescription>
              Create a reusable template for frequently billed claim
              configurations.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit(onCreateSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label
                htmlFor="name"
                className="after:content-['*'] after:ml-0.5 after:text-destructive"
              >
                Template Name
              </Label>
              <Input
                id="name"
                placeholder="e.g., Standard Office Visit"
                {...register('name', {
                  required: 'Name is required',
                  maxLength: { value: 100, message: 'Max 100 characters' },
                })}
              />
              {errors.name && (
                <p className="text-xs text-destructive">{errors.name.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                placeholder="Optional description..."
                rows={2}
                {...register('description', {
                  maxLength: { value: 500, message: 'Max 500 characters' },
                })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="claim_type">Claim Type</Label>
              <Select
                value={watch('claim_type')}
                onValueChange={(val) =>
                  setValue('claim_type', val as 'AHCIP' | 'WCB')
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="AHCIP">AHCIP</SelectItem>
                  <SelectItem value="WCB">WCB</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label
                  htmlFor="hsc_code"
                  className="after:content-['*'] after:ml-0.5 after:text-destructive"
                >
                  HSC Code
                </Label>
                <Input
                  id="hsc_code"
                  placeholder="e.g., 03.04A"
                  className="font-mono"
                  {...register('hsc_code', {
                    required: 'HSC code is required',
                  })}
                />
                {errors.hsc_code && (
                  <p className="text-xs text-destructive">
                    {errors.hsc_code.message}
                  </p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="calls">Calls</Label>
                <Input
                  id="calls"
                  type="number"
                  min={1}
                  {...register('calls', { valueAsNumber: true })}
                />
              </div>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createTemplate.isPending}>
                {createTemplate.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Create Template
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
