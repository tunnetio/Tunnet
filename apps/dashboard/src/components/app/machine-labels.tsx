import { PlusIcon, TrashIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

type LabelRow = {
  id: string;
  key: string;
  value: string;
};

function createLabelRow(key = "", value = ""): LabelRow {
  return { id: crypto.randomUUID(), key, value };
}

type MachineLabelsEditorProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  labels: Record<string, string>;
  onSave: (patch: Record<string, string | null>) => Promise<void>;
  loading?: boolean;
};

export function MachineLabelsEditor({
  open,
  onOpenChange,
  labels,
  onSave,
  loading,
}: MachineLabelsEditorProps) {
  const [rows, setRows] = useState<LabelRow[]>([]);

  useEffect(() => {
    if (!open) return;
    const entries = Object.entries(labels).map(([key, value]) =>
      createLabelRow(key, value),
    );
    setRows(entries.length > 0 ? entries : [createLabelRow()]);
  }, [open, labels]);

  const hasIncompleteRow = rows.some(
    (row) =>
      (row.key.trim() === "" && row.value.trim() !== "") ||
      (row.key.trim() !== "" && row.value.trim() === ""),
  );

  const removeRow = (id: string) => {
    setRows((current) => {
      const next = current.filter((row) => row.id !== id);
      return next.length > 0 ? next : [createLabelRow()];
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit labels</DialogTitle>
          <DialogDescription>
            Key/value tags for filtering and organizing machines.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="text-muted-foreground grid grid-cols-[1fr_1fr_2rem] gap-2 px-0.5 text-[11px] font-medium tracking-wide uppercase">
            <span>Key</span>
            <span>Value</span>
            <span className="sr-only">Remove</span>
          </div>

          <div className="space-y-2">
            {rows.map((row) => (
              <div
                key={row.id}
                className="grid grid-cols-[1fr_1fr_2rem] items-center gap-2"
              >
                <Input
                  className="font-mono text-sm"
                  placeholder="env"
                  value={row.key}
                  onChange={(e) => {
                    setRows((current) =>
                      current.map((item) =>
                        item.id === row.id
                          ? { ...item, key: e.target.value }
                          : item,
                      ),
                    );
                  }}
                />
                <Input
                  className="font-mono text-sm"
                  placeholder="production"
                  value={row.value}
                  onChange={(e) => {
                    setRows((current) =>
                      current.map((item) =>
                        item.id === row.id
                          ? { ...item, value: e.target.value }
                          : item,
                      ),
                    );
                  }}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  aria-label="Remove label"
                  onClick={() => removeRow(row.id)}
                >
                  <TrashIcon className="size-3.5" />
                </Button>
              </div>
            ))}
          </div>

          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={hasIncompleteRow}
            onClick={() => setRows((current) => [...current, createLabelRow()])}
          >
            <PlusIcon className="mr-1.5 size-3.5" />
            Add label
          </Button>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            disabled={loading}
            onClick={() => {
              const filled = rows.filter(
                (row) => row.key.trim() !== "" || row.value.trim() !== "",
              );
              if (
                filled.some(
                  (row) => row.key.trim() === "" || row.value.trim() === "",
                )
              ) {
                toast.error("Each label needs both a key and a value");
                return;
              }

              const patch: Record<string, string | null> = {};
              const seen = new Set<string>();
              for (const row of filled) {
                const key = row.key.trim();
                seen.add(key);
                patch[key] = row.value.trim();
              }
              for (const key of Object.keys(labels)) {
                if (!seen.has(key)) patch[key] = null;
              }

              void onSave(patch)
                .then(() => {
                  toast.success("Labels updated");
                  onOpenChange(false);
                })
                .catch((err: Error) => toast.error(err.message));
            }}
          >
            {loading ? "Saving..." : "Save labels"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function MachineLabelChips({
  labels,
  max = 4,
  className,
  empty = "No labels",
}: {
  labels: Record<string, string>;
  max?: number;
  className?: string;
  empty?: string | null;
}) {
  const entries = Object.entries(labels);
  if (entries.length === 0) {
    return empty ? (
      <span className={cn("text-muted-foreground text-xs", className)}>
        {empty}
      </span>
    ) : null;
  }

  const visible = entries.slice(0, max);
  const hidden = entries.length - visible.length;

  return (
    <div className={cn("flex flex-wrap gap-1.5", className)}>
      {visible.map(([key, value]) => (
        <span
          key={key}
          className="bg-secondary/80 text-secondary-foreground inline-flex max-w-full items-center gap-1 rounded-md px-1.5 py-0.5 font-mono text-[11px] leading-none"
          title={`${key}=${value}`}
        >
          <span className="text-muted-foreground shrink-0">{key}</span>
          <span className="text-muted-foreground/50">=</span>
          <span className="truncate">{value}</span>
        </span>
      ))}
      {hidden > 0 ? (
        <span className="text-muted-foreground inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px]">
          +{hidden}
        </span>
      ) : null}
    </div>
  );
}

type MachineExpiryDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  current: string | null;
  onSave: (expiresIn: string | null) => Promise<void>;
  loading?: boolean;
};

export function MachineExpiryDialog({
  open,
  onOpenChange,
  current,
  onSave,
  loading,
}: MachineExpiryDialogProps) {
  const [value, setValue] = useState(current ?? "");

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) setValue(current ?? "");
        onOpenChange(next);
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Inactivity expiry</DialogTitle>
          <DialogDescription>
            Delete or expire this machine if it stops contacting the control
            plane.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="machine-expiry">Expires after</Label>
          <Input
            id="machine-expiry"
            placeholder="7d, 12h, 50s, or never"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="font-mono"
          />
          <p className="text-muted-foreground text-xs leading-relaxed">
            Leave blank or type <span className="font-mono">never</span> to
            disable. Any heartbeat resets the clock.
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            disabled={loading}
            onClick={() => {
              const trimmed = value.trim();
              const next =
                trimmed === "" || trimmed.toLowerCase() === "never"
                  ? null
                  : trimmed;
              void onSave(next)
                .then(() => {
                  toast.success(
                    next ? "Expiry updated" : "Auto-expiry removed",
                  );
                  onOpenChange(false);
                })
                .catch((err: Error) => toast.error(err.message));
            }}
          >
            {loading ? "Saving..." : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
