'use client';

import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import {
  useWcbConfigs,
  useCreateWcbConfig,
  useUpdateWcbConfig,
  useDeleteWcbConfig,
  type WcbConfig,
} from '@/hooks/api/use-providers';
import { DataTable } from '@/components/data-table/data-table';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
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
import { Loader2, Plus, Pencil, Trash2, HardHat } from 'lucide-react';

const ROLE_CODE_OPTIONS = [
  { value: 'PHY', label: 'Physician' },
  { value: 'SUR', label: 'Surgeon' },
  { value: 'CON', label: 'Consultant' },
  { value: 'ANE', label: 'Anesthesiologist' },
  { value: 'AST', label: 'Assistant' },
];

const SKILL_CODE_OPTIONS = [
  { value: 'GP', label: 'General Practitioner' },
  { value: 'IM', label: 'Internal Medicine' },
  { value: 'OR', label: 'Orthopedic Surgery' },
  { value: 'PM', label: 'Physical Medicine' },
  { value: 'PS', label: 'Plastic Surgery' },
  { value: 'NS', label: 'Neurosurgery' },
];

interface WcbFormState {
  contract_id: string;
  role_code: string;
  skill_code: string;
  is_default: boolean;
}

const defaultFormState: WcbFormState = {
  contract_id: '',
  role_code: 'PHY',
  skill_code: 'GP',
  is_default: false,
};

export default function WcbConfigPage() {
  const { data, isLoading } = useWcbConfigs();
  const createConfig = useCreateWcbConfig();
  const updateConfig = useUpdateWcbConfig();
  const deleteConfig = useDeleteWcbConfig();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingConfig, setEditingConfig] = useState<WcbConfig | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [form, setForm] = useState<WcbFormState>(defaultFormState);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const configs = data?.data ?? [];

  const openCreate = () => {
    setEditingConfig(null);
    setForm(defaultFormState);
    setErrors({});
    setDialogOpen(true);
  };

  const openEdit = (config: WcbConfig) => {
    setEditingConfig(config);
    setForm({
      contract_id: config.contract_id,
      role_code: config.role_code,
      skill_code: config.skill_code,
      is_default: config.is_default,
    });
    setErrors({});
    setDialogOpen(true);
  };

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!form.contract_id.trim()) newErrors.contract_id = 'Contract ID is required';
    if (!form.role_code) newErrors.role_code = 'Role code is required';
    if (!form.skill_code) newErrors.skill_code = 'Skill code is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    const payload = {
      contract_id: form.contract_id,
      role_code: form.role_code,
      skill_code: form.skill_code,
      is_default: form.is_default,
    };

    if (editingConfig) {
      updateConfig.mutate(
        { id: editingConfig.id, ...payload },
        { onSuccess: () => setDialogOpen(false) }
      );
    } else {
      createConfig.mutate(payload as Parameters<typeof createConfig.mutate>[0], {
        onSuccess: () => setDialogOpen(false),
      });
    }
  };

  const handleDelete = () => {
    if (!deleteId) return;
    deleteConfig.mutate(deleteId, {
      onSuccess: () => setDeleteId(null),
    });
  };

  const columns: ColumnDef<WcbConfig>[] = [
    {
      accessorKey: 'contract_id',
      header: 'Contract ID',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <HardHat className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.contract_id}</span>
        </div>
      ),
    },
    {
      accessorKey: 'role_code',
      header: 'Role Code',
      cell: ({ row }) => {
        const opt = ROLE_CODE_OPTIONS.find((o) => o.value === row.original.role_code);
        return (
          <Badge variant="outline">
            {row.original.role_code} {opt ? `- ${opt.label}` : ''}
          </Badge>
        );
      },
    },
    {
      accessorKey: 'skill_code',
      header: 'Skill Code',
      cell: ({ row }) => {
        const opt = SKILL_CODE_OPTIONS.find((o) => o.value === row.original.skill_code);
        return (
          <Badge variant="outline">
            {row.original.skill_code} {opt ? `- ${opt.label}` : ''}
          </Badge>
        );
      },
    },
    {
      accessorKey: 'is_default',
      header: 'Default',
      cell: ({ row }) =>
        row.original.is_default ? (
          <Badge variant="success">Default</Badge>
        ) : (
          <span className="text-muted-foreground text-sm">-</span>
        ),
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => openEdit(row.original)}>
            <Pencil className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setDeleteId(row.original.id)}>
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  const isSaving = createConfig.isPending || updateConfig.isPending;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">WCB Configuration</h2>
        <p className="text-muted-foreground">
          Manage your Workers&apos; Compensation Board billing configurations
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>WCB Configs</CardTitle>
              <CardDescription>
                Configure contract IDs, role codes, and skill codes for WCB billing
              </CardDescription>
            </div>
            <Button onClick={openCreate} size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Add Config
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={configs} isLoading={isLoading} />
        </CardContent>
      </Card>

      {/* Create / Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingConfig ? 'Edit WCB Configuration' : 'New WCB Configuration'}
            </DialogTitle>
            <DialogDescription>
              {editingConfig
                ? 'Update the WCB billing configuration.'
                : 'Add a new WCB billing configuration.'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="contract_id">Contract ID</Label>
              <Input
                id="contract_id"
                value={form.contract_id}
                onChange={(e) => setForm((prev) => ({ ...prev, contract_id: e.target.value }))}
                placeholder="e.g., WCB-2024-001"
              />
              {errors.contract_id && (
                <p className="text-sm text-destructive">{errors.contract_id}</p>
              )}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="role_code">Role Code</Label>
                <Select
                  value={form.role_code}
                  onValueChange={(v) => setForm((prev) => ({ ...prev, role_code: v }))}
                >
                  <SelectTrigger id="role_code">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ROLE_CODE_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.value} - {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.role_code && (
                  <p className="text-sm text-destructive">{errors.role_code}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="skill_code">Skill Code</Label>
                <Select
                  value={form.skill_code}
                  onValueChange={(v) => setForm((prev) => ({ ...prev, skill_code: v }))}
                >
                  <SelectTrigger id="skill_code">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SKILL_CODE_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.value} - {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.skill_code && (
                  <p className="text-sm text-destructive">{errors.skill_code}</p>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label htmlFor="is_default">Default Configuration</Label>
                <p className="text-xs text-muted-foreground">
                  Use this configuration as the default for new WCB claims
                </p>
              </div>
              <Switch
                id="is_default"
                checked={form.is_default}
                onCheckedChange={(checked) =>
                  setForm((prev) => ({ ...prev, is_default: checked }))
                }
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSaving}>
                {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingConfig ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete WCB Configuration</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this WCB configuration? Existing WCB claims using
              this configuration will not be affected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleteConfig.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteConfig.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
