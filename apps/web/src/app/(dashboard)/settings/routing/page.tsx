'use client';

import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import {
  useRoutingConfig,
  useCreateFacilityMapping,
  useUpdateFacilityMapping,
  useDeleteFacilityMapping,
  useCreateScheduleMapping,
  useUpdateScheduleMapping,
  useDeleteScheduleMapping,
  type FacilityBaMapping,
  type ScheduleBaMapping,
} from '@/hooks/api/use-providers';
import { DataTable } from '@/components/data-table/data-table';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
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
import { Loader2, Plus, Pencil, Trash2, Route } from 'lucide-react';

const DAYS_OF_WEEK = [
  { value: '0', label: 'Sunday' },
  { value: '1', label: 'Monday' },
  { value: '2', label: 'Tuesday' },
  { value: '3', label: 'Wednesday' },
  { value: '4', label: 'Thursday' },
  { value: '5', label: 'Friday' },
  { value: '6', label: 'Saturday' },
];

// ---------- Facility Form ----------

interface FacilityFormState {
  facility_number: string;
  ba_id: string;
  ba_number: string;
  priority: number;
}

const defaultFacilityForm: FacilityFormState = {
  facility_number: '',
  ba_id: '',
  ba_number: '',
  priority: 1,
};

// ---------- Schedule Form ----------

interface ScheduleFormState {
  day_of_week: number;
  start_time: string;
  end_time: string;
  ba_id: string;
  ba_number: string;
  priority: number;
}

const defaultScheduleForm: ScheduleFormState = {
  day_of_week: 1,
  start_time: '08:00',
  end_time: '17:00',
  ba_id: '',
  ba_number: '',
  priority: 1,
};

export default function RoutingPage() {
  const { data, isLoading } = useRoutingConfig();

  const createFacility = useCreateFacilityMapping();
  const updateFacility = useUpdateFacilityMapping();
  const deleteFacility = useDeleteFacilityMapping();

  const createSchedule = useCreateScheduleMapping();
  const updateSchedule = useUpdateScheduleMapping();
  const deleteSchedule = useDeleteScheduleMapping();

  // Facility state
  const [facilityDialogOpen, setFacilityDialogOpen] = useState(false);
  const [editingFacility, setEditingFacility] = useState<FacilityBaMapping | null>(null);
  const [facilityForm, setFacilityForm] = useState<FacilityFormState>(defaultFacilityForm);
  const [facilityErrors, setFacilityErrors] = useState<Record<string, string>>({});
  const [deleteFacilityId, setDeleteFacilityId] = useState<string | null>(null);

  // Schedule state
  const [scheduleDialogOpen, setScheduleDialogOpen] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState<ScheduleBaMapping | null>(null);
  const [scheduleForm, setScheduleForm] = useState<ScheduleFormState>(defaultScheduleForm);
  const [scheduleErrors, setScheduleErrors] = useState<Record<string, string>>({});
  const [deleteScheduleId, setDeleteScheduleId] = useState<string | null>(null);

  const facilityMappings = data?.data?.facility_mappings ?? [];
  const scheduleMappings = data?.data?.schedule_mappings ?? [];

  // ---------- Facility handlers ----------

  const openCreateFacility = () => {
    setEditingFacility(null);
    setFacilityForm(defaultFacilityForm);
    setFacilityErrors({});
    setFacilityDialogOpen(true);
  };

  const openEditFacility = (mapping: FacilityBaMapping) => {
    setEditingFacility(mapping);
    setFacilityForm({
      facility_number: mapping.facility_number,
      ba_id: mapping.ba_id,
      ba_number: mapping.ba_number,
      priority: mapping.priority,
    });
    setFacilityErrors({});
    setFacilityDialogOpen(true);
  };

  const validateFacility = () => {
    const e: Record<string, string> = {};
    if (!facilityForm.facility_number.trim()) e.facility_number = 'Facility number is required';
    if (!facilityForm.ba_number.trim()) e.ba_number = 'BA number is required';
    if (facilityForm.priority < 1) e.priority = 'Priority must be at least 1';
    setFacilityErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleFacilitySubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateFacility()) return;

    const payload = {
      facility_number: facilityForm.facility_number,
      ba_id: facilityForm.ba_id,
      ba_number: facilityForm.ba_number,
      priority: facilityForm.priority,
    };

    if (editingFacility) {
      updateFacility.mutate(
        { id: editingFacility.id, ...payload },
        { onSuccess: () => setFacilityDialogOpen(false) }
      );
    } else {
      createFacility.mutate(payload, {
        onSuccess: () => setFacilityDialogOpen(false),
      });
    }
  };

  const handleDeleteFacility = () => {
    if (!deleteFacilityId) return;
    deleteFacility.mutate(deleteFacilityId, {
      onSuccess: () => setDeleteFacilityId(null),
    });
  };

  // ---------- Schedule handlers ----------

  const openCreateSchedule = () => {
    setEditingSchedule(null);
    setScheduleForm(defaultScheduleForm);
    setScheduleErrors({});
    setScheduleDialogOpen(true);
  };

  const openEditSchedule = (mapping: ScheduleBaMapping) => {
    setEditingSchedule(mapping);
    setScheduleForm({
      day_of_week: mapping.day_of_week,
      start_time: mapping.start_time,
      end_time: mapping.end_time,
      ba_id: mapping.ba_id,
      ba_number: mapping.ba_number,
      priority: mapping.priority,
    });
    setScheduleErrors({});
    setScheduleDialogOpen(true);
  };

  const validateSchedule = () => {
    const e: Record<string, string> = {};
    if (!scheduleForm.ba_number.trim()) e.ba_number = 'BA number is required';
    if (!scheduleForm.start_time) e.start_time = 'Start time is required';
    if (!scheduleForm.end_time) e.end_time = 'End time is required';
    if (scheduleForm.priority < 1) e.priority = 'Priority must be at least 1';
    setScheduleErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleScheduleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateSchedule()) return;

    const payload = {
      day_of_week: scheduleForm.day_of_week,
      start_time: scheduleForm.start_time,
      end_time: scheduleForm.end_time,
      ba_id: scheduleForm.ba_id,
      ba_number: scheduleForm.ba_number,
      priority: scheduleForm.priority,
    };

    if (editingSchedule) {
      updateSchedule.mutate(
        { id: editingSchedule.id, ...payload },
        { onSuccess: () => setScheduleDialogOpen(false) }
      );
    } else {
      createSchedule.mutate(payload, {
        onSuccess: () => setScheduleDialogOpen(false),
      });
    }
  };

  const handleDeleteSchedule = () => {
    if (!deleteScheduleId) return;
    deleteSchedule.mutate(deleteScheduleId, {
      onSuccess: () => setDeleteScheduleId(null),
    });
  };

  // ---------- Column defs ----------

  const facilityColumns: ColumnDef<FacilityBaMapping>[] = [
    { accessorKey: 'facility_number', header: 'Facility Number' },
    { accessorKey: 'ba_number', header: 'BA Number' },
    {
      accessorKey: 'priority',
      header: 'Priority',
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.priority}</span>
      ),
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => openEditFacility(row.original)}>
            <Pencil className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setDeleteFacilityId(row.original.id)}>
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  const scheduleColumns: ColumnDef<ScheduleBaMapping>[] = [
    {
      accessorKey: 'day_of_week',
      header: 'Day',
      cell: ({ row }) => {
        const day = DAYS_OF_WEEK.find((d) => Number(d.value) === row.original.day_of_week);
        return day?.label ?? row.original.day_of_week;
      },
    },
    {
      id: 'time_range',
      header: 'Time Range',
      cell: ({ row }) => `${row.original.start_time} - ${row.original.end_time}`,
    },
    { accessorKey: 'ba_number', header: 'BA Number' },
    {
      accessorKey: 'priority',
      header: 'Priority',
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.priority}</span>
      ),
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={() => openEditSchedule(row.original)}>
            <Pencil className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setDeleteScheduleId(row.original.id)}>
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  const isFacilitySaving = createFacility.isPending || updateFacility.isPending;
  const isScheduleSaving = createSchedule.isPending || updateSchedule.isPending;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Smart Routing</h2>
        <p className="text-muted-foreground">
          Configure automatic BA selection based on facility or schedule
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Route className="h-5 w-5" />
            Routing Rules
          </CardTitle>
          <CardDescription>
            Smart routing automatically selects the correct business arrangement based on where and
            when you practice
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="facility">
            <TabsList>
              <TabsTrigger value="facility">Facility Mappings</TabsTrigger>
              <TabsTrigger value="schedule">Schedule Mappings</TabsTrigger>
            </TabsList>

            <TabsContent value="facility" className="space-y-4">
              <div className="flex justify-end">
                <Button onClick={openCreateFacility} size="sm">
                  <Plus className="mr-2 h-4 w-4" />
                  Add Facility Mapping
                </Button>
              </div>
              <DataTable
                columns={facilityColumns}
                data={facilityMappings}
                isLoading={isLoading}
              />
            </TabsContent>

            <TabsContent value="schedule" className="space-y-4">
              <div className="flex justify-end">
                <Button onClick={openCreateSchedule} size="sm">
                  <Plus className="mr-2 h-4 w-4" />
                  Add Schedule Mapping
                </Button>
              </div>
              <DataTable
                columns={scheduleColumns}
                data={scheduleMappings}
                isLoading={isLoading}
              />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Facility Dialog */}
      <Dialog open={facilityDialogOpen} onOpenChange={setFacilityDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingFacility ? 'Edit Facility Mapping' : 'New Facility Mapping'}
            </DialogTitle>
            <DialogDescription>
              Map a facility to a specific business arrangement for automatic routing.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleFacilitySubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="fac_facility_number">Facility Number</Label>
              <Input
                id="fac_facility_number"
                value={facilityForm.facility_number}
                onChange={(e) =>
                  setFacilityForm((prev) => ({ ...prev, facility_number: e.target.value }))
                }
              />
              {facilityErrors.facility_number && (
                <p className="text-sm text-destructive">{facilityErrors.facility_number}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="fac_ba_number">BA Number</Label>
              <Input
                id="fac_ba_number"
                value={facilityForm.ba_number}
                onChange={(e) =>
                  setFacilityForm((prev) => ({ ...prev, ba_number: e.target.value }))
                }
              />
              {facilityErrors.ba_number && (
                <p className="text-sm text-destructive">{facilityErrors.ba_number}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="fac_priority">Priority</Label>
              <Input
                id="fac_priority"
                type="number"
                min={1}
                value={facilityForm.priority}
                onChange={(e) =>
                  setFacilityForm((prev) => ({ ...prev, priority: Number(e.target.value) }))
                }
                className="w-24"
              />
              {facilityErrors.priority && (
                <p className="text-sm text-destructive">{facilityErrors.priority}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Lower numbers have higher priority.
              </p>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setFacilityDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={isFacilitySaving}>
                {isFacilitySaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingFacility ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Schedule Dialog */}
      <Dialog open={scheduleDialogOpen} onOpenChange={setScheduleDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingSchedule ? 'Edit Schedule Mapping' : 'New Schedule Mapping'}
            </DialogTitle>
            <DialogDescription>
              Map a day and time range to a specific business arrangement.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleScheduleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sched_day">Day of Week</Label>
              <Select
                value={String(scheduleForm.day_of_week)}
                onValueChange={(v) =>
                  setScheduleForm((prev) => ({ ...prev, day_of_week: Number(v) }))
                }
              >
                <SelectTrigger id="sched_day">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DAYS_OF_WEEK.map((d) => (
                    <SelectItem key={d.value} value={d.value}>
                      {d.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="sched_start">Start Time</Label>
                <Input
                  id="sched_start"
                  type="time"
                  value={scheduleForm.start_time}
                  onChange={(e) =>
                    setScheduleForm((prev) => ({ ...prev, start_time: e.target.value }))
                  }
                />
                {scheduleErrors.start_time && (
                  <p className="text-sm text-destructive">{scheduleErrors.start_time}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="sched_end">End Time</Label>
                <Input
                  id="sched_end"
                  type="time"
                  value={scheduleForm.end_time}
                  onChange={(e) =>
                    setScheduleForm((prev) => ({ ...prev, end_time: e.target.value }))
                  }
                />
                {scheduleErrors.end_time && (
                  <p className="text-sm text-destructive">{scheduleErrors.end_time}</p>
                )}
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="sched_ba_number">BA Number</Label>
              <Input
                id="sched_ba_number"
                value={scheduleForm.ba_number}
                onChange={(e) =>
                  setScheduleForm((prev) => ({ ...prev, ba_number: e.target.value }))
                }
              />
              {scheduleErrors.ba_number && (
                <p className="text-sm text-destructive">{scheduleErrors.ba_number}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="sched_priority">Priority</Label>
              <Input
                id="sched_priority"
                type="number"
                min={1}
                value={scheduleForm.priority}
                onChange={(e) =>
                  setScheduleForm((prev) => ({ ...prev, priority: Number(e.target.value) }))
                }
                className="w-24"
              />
              {scheduleErrors.priority && (
                <p className="text-sm text-destructive">{scheduleErrors.priority}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Lower numbers have higher priority.
              </p>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setScheduleDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={isScheduleSaving}>
                {isScheduleSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingSchedule ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Facility Confirmation */}
      <AlertDialog
        open={!!deleteFacilityId}
        onOpenChange={(open) => !open && setDeleteFacilityId(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Facility Mapping</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this facility-to-BA routing rule?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteFacility}
              disabled={deleteFacility.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteFacility.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Schedule Confirmation */}
      <AlertDialog
        open={!!deleteScheduleId}
        onOpenChange={(open) => !open && setDeleteScheduleId(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Schedule Mapping</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this schedule-to-BA routing rule?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteSchedule}
              disabled={deleteSchedule.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteSchedule.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
