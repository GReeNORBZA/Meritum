'use client';

import * as React from 'react';
import {
  type ColumnDef,
  type SortingState,
  type OnChangeFn,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { DataTablePagination } from '@/components/data-table/data-table-pagination';

interface DataTablePaginationState {
  page: number;
  pageSize: number;
  total: number;
}

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
  isLoading?: boolean;
  pagination?: DataTablePaginationState;
  onPaginationChange?: (page: number, pageSize: number) => void;
  sorting?: SortingState;
  onSortingChange?: OnChangeFn<SortingState>;
  toolbar?: React.ReactNode;
}

function DataTable<TData, TValue>({
  columns,
  data,
  isLoading,
  pagination,
  onPaginationChange,
  sorting: controlledSorting,
  onSortingChange,
  toolbar,
}: DataTableProps<TData, TValue>) {
  const [internalSorting, setInternalSorting] = React.useState<SortingState>([]);
  const sorting = controlledSorting ?? internalSorting;
  const handleSortingChange = onSortingChange ?? setInternalSorting;

  const pageCount = pagination
    ? Math.ceil(pagination.total / pagination.pageSize)
    : -1;

  const table = useReactTable({
    data,
    columns,
    state: {
      sorting,
      ...(pagination
        ? {
            pagination: {
              pageIndex: pagination.page - 1,
              pageSize: pagination.pageSize,
            },
          }
        : {}),
    },
    onSortingChange: handleSortingChange,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: onSortingChange ? undefined : getSortedRowModel(),
    manualPagination: !!pagination,
    pageCount,
    manualSorting: !!onSortingChange,
  });

  const skeletonRowCount = pagination?.pageSize ?? 10;

  return (
    <div className="space-y-4">
      {toolbar && <div>{toolbar}</div>}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id} colSpan={header.colSpan}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              Array.from({ length: skeletonRowCount }).map((_, rowIndex) => (
                <TableRow key={`skeleton-${rowIndex}`}>
                  {columns.map((_, colIndex) => (
                    <TableCell key={`skeleton-${rowIndex}-${colIndex}`}>
                      <Skeleton className="h-5 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={row.getIsSelected() && 'selected'}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center"
                >
                  No results.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {pagination && onPaginationChange && (
        <DataTablePagination
          table={table}
          pageSizeOptions={[10, 20, 50]}
          onPageChange={(page) =>
            onPaginationChange(page, pagination.pageSize)
          }
          onPageSizeChange={(pageSize) => onPaginationChange(1, pageSize)}
        />
      )}
    </div>
  );
}

export { DataTable };
export type { DataTableProps, DataTablePaginationState };
