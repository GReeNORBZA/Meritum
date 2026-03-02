'use client';

import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import {
  usePracticeLocations,
  useCreatePracticeLocation,
  useUpdatePracticeLocation,
  useDeletePracticeLocation,
  type PracticeLocation,
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
import { Loader2, Plus, Pencil, Trash2, MapPin } from 'lucide-react';

interface LocationFormState {
  name: string;
  functional_centre: string;
  facility_number: string;
  address_line1: string;
  address_line2: string;
  city: string;
  province: string;
  postal_code: string;
  status: 'active' | 'inactive';
}

const defaultFormState: LocationFormState = {
  name: '',
  functional_centre: '',
  facility_number: '',
  address_line1: '',
  address_line2: '',
  city: '',
  province: 'AB',
  postal_code: '',
  status: 'active',
};

const PROVINCE_OPTIONS = [
  { value: 'AB', label: 'Alberta' },
  { value: 'BC', label: 'British Columbia' },
  { value: 'SK', label: 'Saskatchewan' },
  { value: 'MB', label: 'Manitoba' },
  { value: 'ON', label: 'Ontario' },
  { value: 'QC', label: 'Quebec' },
  { value: 'NB', label: 'New Brunswick' },
  { value: 'NS', label: 'Nova Scotia' },
  { value: 'PE', label: 'Prince Edward Island' },
  { value: 'NL', label: 'Newfoundland and Labrador' },
  { value: 'NT', label: 'Northwest Territories' },
  { value: 'NU', label: 'Nunavut' },
  { value: 'YT', label: 'Yukon' },
];

export default function LocationsPage() {
  const { data, isLoading } = usePracticeLocations();
  const createLocation = useCreatePracticeLocation();
  const updateLocation = useUpdatePracticeLocation();
  const deleteLocation = useDeletePracticeLocation();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingLocation, setEditingLocation] = useState<PracticeLocation | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [form, setForm] = useState<LocationFormState>(defaultFormState);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const locations = data?.data ?? [];

  const openCreate = () => {
    setEditingLocation(null);
    setForm(defaultFormState);
    setErrors({});
    setDialogOpen(true);
  };

  const openEdit = (loc: PracticeLocation) => {
    setEditingLocation(loc);
    setForm({
      name: loc.name,
      functional_centre: loc.functional_centre,
      facility_number: loc.facility_number,
      address_line1: loc.address_line1 ?? '',
      address_line2: loc.address_line2 ?? '',
      city: loc.city,
      province: loc.province,
      postal_code: loc.postal_code,
      status: loc.status,
    });
    setErrors({});
    setDialogOpen(true);
  };

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!form.name.trim()) newErrors.name = 'Name is required';
    if (!form.functional_centre.trim()) newErrors.functional_centre = 'Functional centre is required';
    if (!form.facility_number.trim()) newErrors.facility_number = 'Facility number is required';
    if (!form.city.trim()) newErrors.city = 'City is required';
    if (!form.postal_code.trim()) newErrors.postal_code = 'Postal code is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    const payload = {
      name: form.name,
      functional_centre: form.functional_centre,
      facility_number: form.facility_number,
      address_line1: form.address_line1 || undefined,
      address_line2: form.address_line2 || undefined,
      city: form.city,
      province: form.province,
      postal_code: form.postal_code,
      status: form.status,
    };

    if (editingLocation) {
      updateLocation.mutate(
        { id: editingLocation.id, ...payload },
        { onSuccess: () => setDialogOpen(false) }
      );
    } else {
      createLocation.mutate(payload as Parameters<typeof createLocation.mutate>[0], {
        onSuccess: () => setDialogOpen(false),
      });
    }
  };

  const handleDelete = () => {
    if (!deleteId) return;
    deleteLocation.mutate(deleteId, {
      onSuccess: () => setDeleteId(null),
    });
  };

  const columns: ColumnDef<PracticeLocation>[] = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <MapPin className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.name}</span>
        </div>
      ),
    },
    {
      accessorKey: 'functional_centre',
      header: 'Functional Centre',
    },
    {
      accessorKey: 'facility_number',
      header: 'Facility Number',
    },
    {
      accessorKey: 'city',
      header: 'City',
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => (
        <Badge variant={row.original.status === 'active' ? 'success' : 'secondary'}>
          {row.original.status}
        </Badge>
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

  const isSaving = createLocation.isPending || updateLocation.isPending;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Locations</h2>
        <p className="text-muted-foreground">Manage your practice locations and facilities</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Practice Locations</CardTitle>
              <CardDescription>
                Add and manage the locations where you practice
              </CardDescription>
            </div>
            <Button onClick={openCreate} size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Add Location
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={locations} isLoading={isLoading} />
        </CardContent>
      </Card>

      {/* Create / Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingLocation ? 'Edit Location' : 'New Location'}
            </DialogTitle>
            <DialogDescription>
              {editingLocation
                ? 'Update the details of this practice location.'
                : 'Add a new practice location.'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="loc_name">Location Name</Label>
              <Input
                id="loc_name"
                value={form.name}
                onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
              />
              {errors.name && <p className="text-sm text-destructive">{errors.name}</p>}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="functional_centre">Functional Centre</Label>
                <Input
                  id="functional_centre"
                  value={form.functional_centre}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, functional_centre: e.target.value }))
                  }
                />
                {errors.functional_centre && (
                  <p className="text-sm text-destructive">{errors.functional_centre}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="facility_number">Facility Number</Label>
                <Input
                  id="facility_number"
                  value={form.facility_number}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, facility_number: e.target.value }))
                  }
                />
                {errors.facility_number && (
                  <p className="text-sm text-destructive">{errors.facility_number}</p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="address_line1">Address Line 1</Label>
              <Input
                id="address_line1"
                value={form.address_line1}
                onChange={(e) => setForm((prev) => ({ ...prev, address_line1: e.target.value }))}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="address_line2">Address Line 2</Label>
              <Input
                id="address_line2"
                value={form.address_line2}
                onChange={(e) => setForm((prev) => ({ ...prev, address_line2: e.target.value }))}
              />
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <div className="space-y-2">
                <Label htmlFor="city">City</Label>
                <Input
                  id="city"
                  value={form.city}
                  onChange={(e) => setForm((prev) => ({ ...prev, city: e.target.value }))}
                />
                {errors.city && <p className="text-sm text-destructive">{errors.city}</p>}
              </div>
              <div className="space-y-2">
                <Label htmlFor="province">Province</Label>
                <Select
                  value={form.province}
                  onValueChange={(v) => setForm((prev) => ({ ...prev, province: v }))}
                >
                  <SelectTrigger id="province">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PROVINCE_OPTIONS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="postal_code">Postal Code</Label>
                <Input
                  id="postal_code"
                  value={form.postal_code}
                  onChange={(e) => setForm((prev) => ({ ...prev, postal_code: e.target.value }))}
                  placeholder="T2P 1A1"
                />
                {errors.postal_code && (
                  <p className="text-sm text-destructive">{errors.postal_code}</p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="loc_status">Status</Label>
              <Select
                value={form.status}
                onValueChange={(v) =>
                  setForm((prev) => ({ ...prev, status: v as 'active' | 'inactive' }))
                }
              >
                <SelectTrigger id="loc_status">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="inactive">Inactive</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSaving}>
                {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingLocation ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Location</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this location? This will affect any routing
              configurations associated with this facility.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleteLocation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteLocation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
