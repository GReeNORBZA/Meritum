'use client';

import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import {
  useBusinessArrangements,
  useCreateBusinessArrangement,
  useUpdateBusinessArrangement,
  useDeleteBusinessArrangement,
  type BusinessArrangement,
} from '@/hooks/api/use-providers';
import { DataTable } from '@/components/data-table/data-table';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Loader2, Plus, Pencil, Trash2 } from 'lucide-react';

const BA_TYPE_OPTIONS = ['FFS', 'PCPCM', 'ARP'] as const;
const BA_STATUS_OPTIONS = ['active', 'inactive', 'pending'] as const;

interface BaFormState {
  ba_number: string;
  type: 'FFS' | 'PCPCM' | 'ARP';
  status: 'active' | 'inactive' | 'pending';
  effective_date: string;
  end_date: string;
  facility_number: string;
}

const defaultFormState: BaFormState = {
  ba_number: '',
  type: 'FFS',
  status: 'active',
  effective_date: '',
  end_date: '',
  facility_number: '',
};

function statusBadgeVariant(status: string) {
  switch (status) {
    case 'active':
      return 'success' as const;
    case 'pending':
      return 'warning' as const;
    case 'inactive':
      return 'secondary' as const;
    default:
      return 'default' as const;
  }
}

export default function BusinessArrangementsPage() {
  const { data, isLoading } = useBusinessArrangements();
  const createBa = useCreateBusinessArrangement();
  const updateBa = useUpdateBusinessArrangement();
  const deleteBa = useDeleteBusinessArrangement();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingBa, setEditingBa] = useState<BusinessArrangement | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [form, setForm] = useState<BaFormState>(defaultFormState);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const bas = data?.data ?? [];

  const openCreate = () => {
    setEditingBa(null);
    setForm(defaultFormState);
    setErrors({});
    setDialogOpen(true);
  };

  const openEdit = (ba: BusinessArrangement) => {
    setEditingBa(ba);
    setForm({
      ba_number: ba.ba_number,
      type: ba.type,
      status: ba.status,
      effective_date: ba.effective_date,
      end_date: ba.end_date ?? '',
      facility_number: ba.facility_number ?? '',
    });
    setErrors({});
    setDialogOpen(true);
  };

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!form.ba_number.trim()) newErrors.ba_number = 'BA number is required';
    if (!form.effective_date) newErrors.effective_date = 'Effective date is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    const payload = {
      ba_number: form.ba_number,
      type: form.type,
      status: form.status,
      effective_date: form.effective_date,
      end_date: form.end_date || undefined,
      facility_number: form.facility_number || undefined,
    };

    if (editingBa) {
      updateBa.mutate(
        { id: editingBa.id, ...payload },
        { onSuccess: () => setDialogOpen(false) }
      );
    } else {
      createBa.mutate(payload as Parameters<typeof createBa.mutate>[0], {
        onSuccess: () => setDialogOpen(false),
      });
    }
  };

  const handleDelete = () => {
    if (!deleteId) return;
    deleteBa.mutate(deleteId, {
      onSuccess: () => setDeleteId(null),
    });
  };

  const columns: ColumnDef<BusinessArrangement>[] = [
    {
      accessorKey: 'ba_number',
      header: 'BA Number',
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: ({ row }) => (
        <Badge variant="outline">{row.original.type}</Badge>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => (
        <Badge variant={statusBadgeVariant(row.original.status)}>
          {row.original.status}
        </Badge>
      ),
    },
    {
      accessorKey: 'effective_date',
      header: 'Effective Date',
      cell: ({ row }) => new Date(row.original.effective_date).toLocaleDateString(),
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => openEdit(row.original)}>
            <Pencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setDeleteId(row.original.id)}
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  const isSaving = createBa.isPending || updateBa.isPending;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Business Arrangements</h2>
        <p className="text-muted-foreground">
          Manage your business arrangements (FFS, PCPCM, ARP)
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Arrangements</CardTitle>
              <CardDescription>
                Configure the business arrangements tied to your billing
              </CardDescription>
            </div>
            <Button onClick={openCreate} size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Add Arrangement
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={bas} isLoading={isLoading} />
        </CardContent>
      </Card>

      {/* Create / Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingBa ? 'Edit Business Arrangement' : 'New Business Arrangement'}
            </DialogTitle>
            <DialogDescription>
              {editingBa
                ? 'Update the details of this business arrangement.'
                : 'Add a new business arrangement to your profile.'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="ba_number">BA Number</Label>
              <Input
                id="ba_number"
                value={form.ba_number}
                onChange={(e) => setForm((prev) => ({ ...prev, ba_number: e.target.value }))}
              />
              {errors.ba_number && (
                <p className="text-sm text-destructive">{errors.ba_number}</p>
              )}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="ba_type">Type</Label>
                <Select
                  value={form.type}
                  onValueChange={(v) => setForm((prev) => ({ ...prev, type: v as BaFormState['type'] }))}
                >
                  <SelectTrigger id="ba_type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {BA_TYPE_OPTIONS.map((t) => (
                      <SelectItem key={t} value={t}>
                        {t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="ba_status">Status</Label>
                <Select
                  value={form.status}
                  onValueChange={(v) =>
                    setForm((prev) => ({ ...prev, status: v as BaFormState['status'] }))
                  }
                >
                  <SelectTrigger id="ba_status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {BA_STATUS_OPTIONS.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="effective_date">Effective Date</Label>
                <Input
                  id="effective_date"
                  type="date"
                  value={form.effective_date}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, effective_date: e.target.value }))
                  }
                />
                {errors.effective_date && (
                  <p className="text-sm text-destructive">{errors.effective_date}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="end_date">End Date (optional)</Label>
                <Input
                  id="end_date"
                  type="date"
                  value={form.end_date}
                  onChange={(e) => setForm((prev) => ({ ...prev, end_date: e.target.value }))}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="facility_number">Facility Number (optional)</Label>
              <Input
                id="facility_number"
                value={form.facility_number}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, facility_number: e.target.value }))
                }
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSaving}>
                {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingBa ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Business Arrangement</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this business arrangement? This action cannot be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleteBa.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteBa.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
