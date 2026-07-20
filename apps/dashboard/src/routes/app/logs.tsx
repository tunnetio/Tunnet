import { createFileRoute } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import type { AuditEntry } from "@tunnet/api/management";
import { formatDistanceToNow } from "date-fns";
import { useEffect, useMemo, useState } from "react";
import { DataTable } from "@/components/app/data-table";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useActiveOrganization } from "@/lib/auth-client";
import { createManagementClient } from "@/lib/management-client";
import { useAuditLog } from "@/lib/queries/management";

export const Route = createFileRoute("/app/logs")({
  component: LogsPage,
});

function LogsPage() {
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: initial, isPending } = useAuditLog(orgId);
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    if (initial) {
      setEntries(initial.entries);
      setCursor(initial.nextCursor);
    }
  }, [initial]);

  const columns = useMemo<ColumnDef<AuditEntry>[]>(
    () => [
      {
        id: "time",
        header: "Time",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm whitespace-nowrap">
            {formatDistanceToNow(new Date(row.original.time), {
              addSuffix: true,
            })}
          </span>
        ),
      },
      {
        id: "message",
        header: "Event",
        cell: ({ row }) => (
          <span className="text-sm">{row.original.message}</span>
        ),
      },
      {
        id: "class",
        header: "Class",
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.classUid}
          </span>
        ),
      },
      {
        id: "target",
        header: "Target",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.target.targetType}:
            {row.original.target.targetId || "—"}
          </span>
        ),
      },
      {
        id: "actor",
        header: "Actor",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">
            {row.original.actor.displayName ?? row.original.actor.actorId}
          </span>
        ),
      },
    ],
    [],
  );

  async function loadMore() {
    if (!orgId || cursor === null) return;
    setLoadingMore(true);
    try {
      const result = await createManagementClient(orgId).listAuditLog(cursor);
      setEntries((prev) => [...prev, ...result.entries]);
      setCursor(result.nextCursor);
    } finally {
      setLoadingMore(false);
    }
  }

  if (isPending && entries.length === 0) {
    return (
      <>
        <PageHeader
          title="Logs"
          description="Audit log for your organization."
        />
        <Skeleton className="h-64 w-full" />
      </>
    );
  }

  return (
    <>
      <PageHeader title="Logs" description="Audit log for your organization." />

      <DataTable
        columns={columns}
        data={entries}
        getRowId={(row) => String(row.sequenceNumber)}
        emptyMessage="No audit entries yet."
      />

      {cursor !== null ? (
        <div className="flex justify-center pt-4">
          <Button
            variant="outline"
            onClick={() => void loadMore()}
            disabled={loadingMore}
          >
            {loadingMore ? "Loading..." : "Load more"}
          </Button>
        </div>
      ) : null}
    </>
  );
}
