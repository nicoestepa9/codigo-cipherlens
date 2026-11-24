import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function TableSkeleton({ columns = 5, rows = 6 }: { columns?: number; rows?: number }) {
  return (
    <div className="w-full overflow-hidden rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            {Array.from({ length: columns }).map((_, i) => (
              <TableHead key={i}>
                <Skeleton className="h-4 w-24" />
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: rows }).map((_, r) => (
            <TableRow key={r}>
              {Array.from({ length: columns }).map((_, c) => (
                <TableCell key={c}>
                  <Skeleton className="h-4 w-full max-w-[140px]" />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export function CardSkeleton({ className }: { className?: string }) {
  return (
    <div className={className}>
      <Skeleton className="mb-3 h-4 w-32" />
      <Skeleton className="h-8 w-20" />
    </div>
  );
}
