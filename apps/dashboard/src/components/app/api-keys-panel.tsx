import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
  API_KEY_SCOPES,
  type ApiKey,
  type ApiKeyScope,
} from "@tuntun/api/management";
import { PlusIcon, TrashIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { CopyField } from "@/components/app/copy-field";
import { DataTable } from "@/components/app/data-table";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Skeleton } from "@/components/ui/skeleton";
import { isAdminRole, useMemberRole } from "@/hooks/use-member-role";
import { useActiveOrganization } from "@/lib/auth-client";
import { createManagementClient } from "@/lib/management-client";
import { useApiKeys, useNetworks } from "@/lib/queries/management";
import { queryKeys } from "@/lib/query-keys";

function formatNetworkAccess(
  apiKey: ApiKey,
  networkNames: Map<string, string>,
): string {
  if (apiKey.networkIds === null) {
    return "All networks";
  }
  if (apiKey.networkIds.length === 0) {
    return "No networks";
  }
  const names = apiKey.networkIds
    .map((id) => networkNames.get(id) ?? id.slice(0, 8))
    .join(", ");
  return names;
}

export function ApiKeysPanel() {
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: role } = useMemberRole(orgId);
  const isAdmin = isAdminRole(role);
  const { data: apiKeys, isPending } = useApiKeys(orgId);
  const { data: networks } = useNetworks(orgId);
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<string | null>(null);

  const networkNames = useMemo(
    () =>
      new Map((networks ?? []).map((network) => [network.id, network.name])),
    [networks],
  );

  const revoke = useMutation({
    mutationFn: async (keyId: string) => {
      if (!orgId) throw new Error("No organization");
      return createManagementClient(orgId).revokeApiKey(keyId);
    },
    onSuccess: () => {
      if (orgId) {
        void queryClient.invalidateQueries({
          queryKey: queryKeys.apiKeys(orgId),
        });
      }
    },
  });

  const columns = useMemo<ColumnDef<ApiKey>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        cell: ({ row }) => row.original.name,
      },
      {
        id: "networks",
        header: "Networks",
        cell: ({ row }) => (
          <span className="text-sm">
            {formatNetworkAccess(row.original, networkNames)}
          </span>
        ),
      },
      {
        id: "scopes",
        header: "Scopes",
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.scopes.length > 0
              ? row.original.scopes.join(", ")
              : "—"}
          </span>
        ),
      },
      {
        id: "created",
        header: "Created",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-sm">
            {new Date(row.original.createdAt).toLocaleDateString()}
          </span>
        ),
      },
      ...(isAdmin
        ? [
            {
              id: "actions",
              header: "",
              meta: { headerClassName: "w-10" },
              cell: ({ row }: { row: { original: ApiKey } }) => (
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setRevokeId(row.original.id)}
                >
                  <TrashIcon className="size-4" />
                </Button>
              ),
            } satisfies ColumnDef<ApiKey>,
          ]
        : []),
    ],
    [isAdmin, networkNames],
  );

  return (
    <>
      <div className="mb-4 flex justify-end">
        {isAdmin ? (
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <PlusIcon className="mr-1.5 size-4" />
            Create key
          </Button>
        ) : null}
      </div>

      {isPending ? (
        <Skeleton className="h-48 w-full" />
      ) : (
        <DataTable
          columns={columns}
          data={apiKeys ?? []}
          getRowId={(row) => row.id}
        />
      )}

      <CreateApiKeyDialog
        orgId={orgId}
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(secret) => {
          setNewSecret(secret);
          if (orgId) {
            void queryClient.invalidateQueries({
              queryKey: queryKeys.apiKeys(orgId),
            });
          }
        }}
      />

      <Dialog open={newSecret !== null} onOpenChange={() => setNewSecret(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API key created</DialogTitle>
          </DialogHeader>
          {newSecret ? <CopyField label="Secret" value={newSecret} /> : null}
          <DialogFooter>
            <Button onClick={() => setNewSecret(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={revokeId !== null}
        onOpenChange={(open) => !open && setRevokeId(null)}
        title="Revoke API key"
        description="This key will stop working immediately."
        confirmLabel="Revoke"
        destructive
        loading={revoke.isPending}
        onConfirm={async () => {
          if (!revokeId) return;
          try {
            await revoke.mutateAsync(revokeId);
            toast.success("API key revoked");
            setRevokeId(null);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to revoke",
            );
          }
        }}
      />
    </>
  );
}

function CreateApiKeyDialog({
  orgId,
  open,
  onOpenChange,
  onCreated,
}: {
  orgId: string | undefined;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (secret: string) => void;
}) {
  const { data: networks } = useNetworks(orgId);
  const [name, setName] = useState("");
  const [allNetworks, setAllNetworks] = useState(true);
  const [selectedNetworkIds, setSelectedNetworkIds] = useState<string[]>([]);
  const [selectedScopes, setSelectedScopes] = useState<ApiKeyScope[]>([
    "sdk:enroll",
  ]);
  const [loading, setLoading] = useState(false);

  function resetForm() {
    setName("");
    setAllNetworks(true);
    setSelectedNetworkIds([]);
    setSelectedScopes(["sdk:enroll"]);
  }

  function toggleNetwork(networkId: string, checked: boolean) {
    setSelectedNetworkIds((current) =>
      checked
        ? [...current, networkId]
        : current.filter((id) => id !== networkId),
    );
  }

  function toggleScope(scope: ApiKeyScope, checked: boolean) {
    setSelectedScopes((current) =>
      checked ? [...current, scope] : current.filter((id) => id !== scope),
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!orgId) return;

    if (!allNetworks && selectedNetworkIds.length === 0) {
      toast.error("Select at least one network or allow all networks");
      return;
    }
    if (selectedScopes.length === 0) {
      toast.error("Select at least one scope");
      return;
    }

    setLoading(true);
    try {
      const result = await createManagementClient(orgId).createApiKey({
        name: name.trim(),
        scopes: selectedScopes,
        networkIds: allNetworks ? null : selectedNetworkIds,
      });
      toast.success("API key created");
      resetForm();
      onOpenChange(false);
      onCreated(result.secret);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create key");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) resetForm();
        onOpenChange(next);
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={(e) => void handleSubmit(e)}>
          <DialogHeader>
            <DialogTitle>Create API key</DialogTitle>
            <DialogDescription>
              Choose which networks this key can access and what it is allowed
              to do.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-6 py-4">
            <div className="space-y-2">
              <Label htmlFor="key-name">Name</Label>
              <Input
                id="key-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="CI deploy key"
                required
              />
            </div>

            <div className="space-y-3">
              <Label>Networks</Label>
              <div className="flex items-start gap-3 rounded-lg border p-3">
                <Checkbox
                  checked={allNetworks}
                  onCheckedChange={(checked) => {
                    const enabled = checked === true;
                    setAllNetworks(enabled);
                    if (enabled) {
                      setSelectedNetworkIds([]);
                    }
                  }}
                />
                <span className="space-y-1">
                  <span className="block text-sm font-medium">
                    All networks
                  </span>
                  <span className="text-muted-foreground block text-xs">
                    Current and future networks in this organization.
                  </span>
                </span>
              </div>

              {!allNetworks ? (
                <div className="space-y-2 rounded-lg border p-3">
                  {(networks ?? []).length === 0 ? (
                    <p className="text-muted-foreground text-xs">
                      Create a network before restricting access.
                    </p>
                  ) : (
                    (networks ?? []).map((network) => {
                      const checked = selectedNetworkIds.includes(network.id);
                      return (
                        <div
                          key={network.id}
                          className="flex items-center gap-3 py-1"
                        >
                          <Checkbox
                            checked={checked}
                            onCheckedChange={(value) =>
                              toggleNetwork(network.id, value === true)
                            }
                          />
                          <span className="text-sm">{network.name}</span>
                        </div>
                      );
                    })
                  )}
                </div>
              ) : null}
            </div>

            <div className="space-y-3">
              <Label>Scopes</Label>
              <div className="space-y-2">
                {API_KEY_SCOPES.map((scope) => {
                  const checked = selectedScopes.includes(scope.id);
                  return (
                    <div
                      key={scope.id}
                      className="flex items-start gap-3 rounded-lg border p-3"
                    >
                      <Checkbox
                        checked={checked}
                        onCheckedChange={(value) =>
                          toggleScope(scope.id, value === true)
                        }
                      />
                      <span className="space-y-1">
                        <span className="block font-mono text-sm">
                          {scope.id}
                        </span>
                        <span className="text-muted-foreground block text-xs">
                          {scope.description}
                        </span>
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={
                loading ||
                (!allNetworks &&
                  (networks?.length ?? 0) > 0 &&
                  selectedNetworkIds.length === 0) ||
                selectedScopes.length === 0
              }
            >
              {loading ? "Creating..." : "Create key"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
