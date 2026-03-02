'use client';

import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import {
  useDelegates,
  useInviteDelegate,
  useUpdateDelegatePermissions,
  useRevokeDelegate,
  DELEGATE_PERMISSIONS,
  type Delegate,
} from '@/hooks/api/use-delegates';
import { DataTable } from '@/components/data-table/data-table';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
import { Loader2, Plus, Shield, UserX, Pencil, Users } from 'lucide-react';

function statusBadgeVariant(status: string) {
  switch (status) {
    case 'active':
      return 'success' as const;
    case 'pending':
      return 'warning' as const;
    case 'revoked':
      return 'destructive' as const;
    default:
      return 'default' as const;
  }
}

function formatPermission(perm: string): string {
  return perm
    .replace(':', ' ')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function DelegatesPage() {
  const { data, isLoading } = useDelegates();
  const inviteDelegate = useInviteDelegate();
  const updatePermissions = useUpdateDelegatePermissions();
  const revokeDelegate = useRevokeDelegate();

  const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [editingDelegate, setEditingDelegate] = useState<Delegate | null>(null);

  // Invite form
  const [inviteEmail, setInviteEmail] = useState('');
  const [invitePermissions, setInvitePermissions] = useState<string[]>([]);
  const [inviteErrors, setInviteErrors] = useState<Record<string, string>>({});

  // Edit permissions form
  const [editPermissions, setEditPermissions] = useState<string[]>([]);

  const delegates = data?.data ?? [];

  const openInvite = () => {
    setInviteEmail('');
    setInvitePermissions([]);
    setInviteErrors({});
    setInviteDialogOpen(true);
  };

  const openEditPermissions = (delegate: Delegate) => {
    setEditingDelegate(delegate);
    setEditPermissions([...delegate.permissions]);
    setEditDialogOpen(true);
  };

  const toggleInvitePermission = (perm: string) => {
    setInvitePermissions((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]
    );
  };

  const toggleEditPermission = (perm: string) => {
    setEditPermissions((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]
    );
  };

  const validateInvite = () => {
    const errors: Record<string, string> = {};
    if (!inviteEmail.trim()) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(inviteEmail)) {
      errors.email = 'Invalid email address';
    }
    if (invitePermissions.length === 0) {
      errors.permissions = 'At least one permission is required';
    }
    setInviteErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleInvite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateInvite()) return;
    inviteDelegate.mutate(
      { email: inviteEmail, permissions: invitePermissions },
      { onSuccess: () => setInviteDialogOpen(false) }
    );
  };

  const handleUpdatePermissions = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingDelegate || editPermissions.length === 0) return;
    updatePermissions.mutate(
      { id: editingDelegate.id, permissions: editPermissions },
      { onSuccess: () => setEditDialogOpen(false) }
    );
  };

  const handleRevoke = () => {
    if (!revokeId) return;
    revokeDelegate.mutate(revokeId, {
      onSuccess: () => setRevokeId(null),
    });
  };

  const columns: ColumnDef<Delegate>[] = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.name || 'Pending'}</span>
        </div>
      ),
    },
    {
      accessorKey: 'email',
      header: 'Email',
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
      id: 'permissions_count',
      header: 'Permissions',
      cell: ({ row }) => (
        <Badge variant="outline">
          <Shield className="mr-1 h-3 w-3" />
          {row.original.permissions.length}
        </Badge>
      ),
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          {row.original.status !== 'revoked' && (
            <>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => openEditPermissions(row.original)}
              >
                <Pencil className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setRevokeId(row.original.id)}
              >
                <UserX className="h-4 w-4 text-destructive" />
              </Button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Delegates</h2>
        <p className="text-muted-foreground">
          Manage who can access and act on your behalf
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Delegate Access</CardTitle>
              <CardDescription>
                Invite delegates to help manage your billing and claims
              </CardDescription>
            </div>
            <Button onClick={openInvite} size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Invite Delegate
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={delegates} isLoading={isLoading} />
        </CardContent>
      </Card>

      {/* Invite Dialog */}
      <Dialog open={inviteDialogOpen} onOpenChange={setInviteDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Invite Delegate</DialogTitle>
            <DialogDescription>
              Send an invitation to a delegate to help manage your billing. They will receive an
              email to set up their account.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleInvite} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="invite_email">Email Address</Label>
              <Input
                id="invite_email"
                type="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="delegate@example.com"
              />
              {inviteErrors.email && (
                <p className="text-sm text-destructive">{inviteErrors.email}</p>
              )}
            </div>

            <div className="space-y-3">
              <Label>Permissions</Label>
              {inviteErrors.permissions && (
                <p className="text-sm text-destructive">{inviteErrors.permissions}</p>
              )}
              <div className="grid gap-3 sm:grid-cols-2">
                {DELEGATE_PERMISSIONS.map((perm) => (
                  <div key={perm} className="flex items-center space-x-2">
                    <Checkbox
                      id={`invite_perm_${perm}`}
                      checked={invitePermissions.includes(perm)}
                      onCheckedChange={() => toggleInvitePermission(perm)}
                    />
                    <Label
                      htmlFor={`invite_perm_${perm}`}
                      className="text-sm font-normal cursor-pointer"
                    >
                      {formatPermission(perm)}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setInviteDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={inviteDelegate.isPending}>
                {inviteDelegate.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Send Invitation
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Permissions Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Permissions</DialogTitle>
            <DialogDescription>
              Update permissions for {editingDelegate?.name || editingDelegate?.email}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleUpdatePermissions} className="space-y-4">
            <div className="space-y-3">
              <Label>Permissions</Label>
              <div className="grid gap-3 sm:grid-cols-2">
                {DELEGATE_PERMISSIONS.map((perm) => (
                  <div key={perm} className="flex items-center space-x-2">
                    <Checkbox
                      id={`edit_perm_${perm}`}
                      checked={editPermissions.includes(perm)}
                      onCheckedChange={() => toggleEditPermission(perm)}
                    />
                    <Label
                      htmlFor={`edit_perm_${perm}`}
                      className="text-sm font-normal cursor-pointer"
                    >
                      {formatPermission(perm)}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={updatePermissions.isPending || editPermissions.length === 0}
              >
                {updatePermissions.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Update Permissions
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation */}
      <AlertDialog open={!!revokeId} onOpenChange={(open) => !open && setRevokeId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke Delegate Access</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to revoke this delegate&apos;s access? They will no longer be
              able to view or manage your billing.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleRevoke}
              disabled={revokeDelegate.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {revokeDelegate.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Revoke Access
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
