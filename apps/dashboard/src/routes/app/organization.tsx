import { createFileRoute } from "@tanstack/react-router";
import type { AutoCleanupMode } from "@tuntun/api/management";
import {
  formatDurationCompact,
  parseHumanDuration,
  pgIntervalToSeconds,
} from "@tuntun/api/management";
import { formatDistanceToNow } from "date-fns";
import { type ReactNode, useEffect, useState } from "react";
import {
  HiOutlineExclamationTriangle,
  HiOutlineFingerPrint,
  HiOutlineKey,
  HiOutlineLockClosed,
  HiOutlineServer,
  HiOutlineShieldCheck,
  HiOutlineSparkles,
} from "react-icons/hi2";
import { toast } from "sonner";

import { ApiKeysPanel } from "@/components/app/api-keys-panel";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { CopyField } from "@/components/app/copy-field";
import { EntityStatus } from "@/components/app/entity-status";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { isAdminRole, useMemberRole } from "@/hooks/use-member-role";
import { authClient } from "@/lib/auth-client";
import {
  useInternalCa,
  useInternalCaMutations,
  useOrgSettings,
  useOrgSettingsMutations,
  useRelays,
  useSsoSettings,
  useSsoSettingsMutations,
  useTunnelSettings,
  useTunnelSettingsMutations,
} from "@/lib/queries/management";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app/organization")({
  component: OrganizationSettingsPage,
});

type SettingsSection =
  | "general"
  | "machines"
  | "tunnels"
  | "certificate"
  | "api-keys"
  | "sso"
  | "danger";

const sectionMeta: Record<
  SettingsSection,
  { label: string; description: string; icon: typeof HiOutlineSparkles }
> = {
  general: {
    label: "General",
    description: "Name and enrollment",
    icon: HiOutlineSparkles,
  },
  machines: {
    label: "Machines",
    description: "Auto cleanup policy",
    icon: HiOutlineServer,
  },
  tunnels: {
    label: "Tunnels",
    description: "Defaults and domains",
    icon: HiOutlineLockClosed,
  },
  certificate: {
    label: "Certificate",
    description: "Internal CA",
    icon: HiOutlineFingerPrint,
  },
  "api-keys": {
    label: "API keys",
    description: "Programmatic access",
    icon: HiOutlineKey,
  },
  sso: {
    label: "SSO",
    description: "Identity provider",
    icon: HiOutlineShieldCheck,
  },
  danger: {
    label: "Danger zone",
    description: "Irreversible actions",
    icon: HiOutlineExclamationTriangle,
  },
};

const cleanupModes: {
  value: AutoCleanupMode;
  title: string;
  description: string;
}[] = [
  {
    value: "soft",
    title: "Soft-expire",
    description: "Mark as Expired and keep it in the list.",
  },
  {
    value: "hard",
    title: "Delete immediately",
    description: "Remove the machine as soon as it expires.",
  },
  {
    value: "soft_then_hard",
    title: "Soft, then delete",
    description: "Expire first, then hard-delete after a grace period.",
  },
];

function SettingsPanel({
  title,
  description,
  children,
  footer,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <section className="overflow-hidden rounded-xl border border-border/80 bg-card">
      <div className="border-b border-border/70 px-5 py-4 sm:px-6">
        <h2 className="text-sm font-semibold tracking-tight">{title}</h2>
        {description ? (
          <p className="text-muted-foreground mt-1 text-sm leading-relaxed">
            {description}
          </p>
        ) : null}
      </div>
      <div className="px-5 py-5 sm:px-6">{children}</div>
      {footer ? (
        <div className="bg-muted/30 border-t border-border/70 px-5 py-3 sm:px-6">
          {footer}
        </div>
      ) : null}
    </section>
  );
}

function FieldBlock({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {hint ? (
        <p className="text-muted-foreground text-xs leading-relaxed">{hint}</p>
      ) : null}
    </div>
  );
}

function ToggleRow({
  id,
  label,
  description,
  checked,
  onCheckedChange,
  disabled,
}: {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="bg-muted/25 flex items-start justify-between gap-4 rounded-lg border border-border/70 px-4 py-3.5">
      <div className="min-w-0 space-y-1">
        <Label htmlFor={id} className="text-sm font-medium">
          {label}
        </Label>
        <p className="text-muted-foreground text-xs leading-relaxed">
          {description}
        </p>
      </div>
      <Switch
        id={id}
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        className="mt-0.5 shrink-0"
      />
    </div>
  );
}

function OrganizationSettingsPage() {
  const { data: activeOrg } = authClient.useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: role } = useMemberRole(orgId);
  const isAdmin = isAdminRole(role);
  const isOwner = role?.includes("owner") ?? false;
  const [section, setSection] = useState<SettingsSection>("general");
  const [name, setName] = useState(activeOrg?.name ?? "");
  const [quickEnrollEnabled, setQuickEnrollEnabled] = useState(
    activeOrg?.quickEnrollEnabled ?? true,
  );
  const [loading, setLoading] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [rotateOpen, setRotateOpen] = useState(false);

  const { data: ca, isPending: caPending } = useInternalCa(orgId);
  const { data: tunnelSettings, isPending: settingsPending } =
    useTunnelSettings(orgId);
  const { data: orgSettings, isPending: orgSettingsPending } =
    useOrgSettings(orgId);
  const { data: ssoProvider, isPending: ssoPending } = useSsoSettings(orgId);
  const { data: relays } = useRelays(orgId);
  const caMutations = useInternalCaMutations(orgId);
  const settingsMutations = useTunnelSettingsMutations(orgId);
  const orgSettingsMutations = useOrgSettingsMutations(orgId);
  const ssoMutations = useSsoSettingsMutations(orgId);

  const [defaultRelayId, setDefaultRelayId] = useState("auto");
  const [defaultTtl, setDefaultTtl] = useState("");
  const [maxTunnels, setMaxTunnels] = useState("10");
  const [customDomain, setCustomDomain] = useState("");
  const [peerDnsSuffix, setPeerDnsSuffix] = useState("");

  const [cleanupEnabled, setCleanupEnabled] = useState(false);
  const [inactivityAfter, setInactivityAfter] = useState("7d");
  const [cleanupMode, setCleanupMode] = useState<AutoCleanupMode>("soft");
  const [hardDeleteAfter, setHardDeleteAfter] = useState("7d");

  const [ssoDomain, setSsoDomain] = useState("");
  const [issuerUrl, setIssuerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [discoveryUrl, setDiscoveryUrl] = useState("");
  const [scopes, setScopes] = useState("openid profile email");
  const [removeSsoOpen, setRemoveSsoOpen] = useState(false);

  const sections = (
    [
      "general",
      "machines",
      "tunnels",
      "certificate",
      "api-keys",
      "sso",
      ...(isOwner ? (["danger"] as const) : []),
    ] as const
  ).filter(Boolean) as SettingsSection[];

  useEffect(() => {
    if (!tunnelSettings) return;
    setDefaultRelayId(tunnelSettings.defaultRelayId ?? "auto");
    setDefaultTtl(
      tunnelSettings.defaultTtlSeconds
        ? String(tunnelSettings.defaultTtlSeconds)
        : "",
    );
    setMaxTunnels(String(tunnelSettings.maxTunnelsPerMachine));
    setCustomDomain(tunnelSettings.customTunnelDomain ?? "");
    setPeerDnsSuffix(tunnelSettings.peerDnsSuffix ?? "");
  }, [tunnelSettings]);

  useEffect(() => {
    if (!orgSettings) return;
    const ac = orgSettings.machines.autoCleanup;
    setCleanupEnabled(ac.enabled);
    setInactivityAfter(
      ac.inactivityAfter
        ? formatDurationCompact(
            pgIntervalToSeconds(ac.inactivityAfter) ??
              parseHumanDuration(ac.inactivityAfter) ??
              0,
          ) || "7d"
        : "7d",
    );
    setCleanupMode(ac.mode);
    setHardDeleteAfter(
      ac.hardDeleteAfter
        ? formatDurationCompact(
            pgIntervalToSeconds(ac.hardDeleteAfter) ??
              parseHumanDuration(ac.hardDeleteAfter) ??
              0,
          ) || "7d"
        : "7d",
    );
  }, [orgSettings]);

  useEffect(() => {
    if (!ssoProvider) {
      setSsoDomain("");
      setIssuerUrl("");
      setClientId("");
      setDiscoveryUrl("");
      setScopes("openid profile email");
      setClientSecret("");
      return;
    }
    setSsoDomain(ssoProvider.domain);
    setIssuerUrl(ssoProvider.issuer);
    setClientId(ssoProvider.clientId ?? "");
    setDiscoveryUrl(ssoProvider.discoveryEndpoint ?? "");
    setScopes(ssoProvider.scopes.join(" ") || "openid profile email");
    setClientSecret("");
  }, [ssoProvider]);

  useEffect(() => {
    if (!activeOrg) return;
    setName(activeOrg.name);
    setQuickEnrollEnabled(activeOrg.quickEnrollEnabled ?? true);
  }, [activeOrg]);

  useEffect(() => {
    if (section === "danger" && !isOwner) {
      setSection("general");
    }
  }, [section, isOwner]);

  async function saveGeneral(e: React.FormEvent) {
    e.preventDefault();
    if (!orgId) return;
    setLoading(true);
    const { error } = await authClient.organization.update({
      organizationId: orgId,
      data: {
        name: name.trim(),
        quickEnrollEnabled,
      },
    });
    setLoading(false);
    if (error) {
      toast.error(error.message ?? "Failed to update organization");
      return;
    }
    toast.success("Organization updated");
  }

  async function deleteOrg() {
    if (!orgId || deleteConfirm !== activeOrg?.name) return;
    const { error } = await authClient.organization.delete({
      organizationId: orgId,
    });
    if (error) {
      toast.error(error.message ?? "Failed to delete organization");
      return;
    }
    toast.success("Organization deleted");
    window.location.href = "/app/onboarding";
  }

  async function saveTunnelSettings(e: React.FormEvent) {
    e.preventDefault();
    try {
      await settingsMutations.update.mutateAsync({
        defaultRelayId: defaultRelayId === "auto" ? null : defaultRelayId,
        defaultTtlSeconds: defaultTtl.trim() ? Number(defaultTtl) : null,
        maxTunnelsPerMachine: Number(maxTunnels) || 10,
        customTunnelDomain: customDomain.trim() || null,
        peerDnsSuffix: peerDnsSuffix.trim() || null,
      });
      toast.success("Tunnel settings saved");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save");
    }
  }

  async function saveMachineSettings(e: React.FormEvent) {
    e.preventDefault();
    try {
      await orgSettingsMutations.update.mutateAsync({
        machines: {
          autoCleanup: {
            enabled: cleanupEnabled,
            inactivityAfter: cleanupEnabled
              ? inactivityAfter.trim() || null
              : null,
            mode: cleanupMode,
            hardDeleteAfter:
              cleanupEnabled && cleanupMode === "soft_then_hard"
                ? hardDeleteAfter.trim() || null
                : null,
          },
        },
      });
      toast.success("Machine settings saved");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save");
    }
  }

  async function saveSsoSettings(e: React.FormEvent) {
    e.preventDefault();
    try {
      await ssoMutations.upsert.mutateAsync({
        issuer: issuerUrl.trim(),
        domain: ssoDomain.trim(),
        clientId: clientId.trim(),
        ...(clientSecret.trim() ? { clientSecret: clientSecret.trim() } : {}),
        discoveryEndpoint: discoveryUrl.trim() || null,
        scopes: scopes.trim().split(/\s+/).filter(Boolean),
      });
      toast.success("SSO settings saved");
      setClientSecret("");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save");
    }
  }

  async function removeSsoSettings() {
    try {
      await ssoMutations.remove.mutateAsync();
      toast.success("SSO provider removed");
      setRemoveSsoOpen(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to remove");
    }
  }

  return (
    <>
      <PageHeader
        title="Organization"
        description="Configure organization profile, machines, tunnels, and security."
      />

      <div className="flex flex-col gap-6 sm:flex-row sm:gap-8">
        <nav
          aria-label="Organization settings sections"
          className="flex shrink-0 gap-1 overflow-x-auto pb-1 sm:w-44 sm:flex-col sm:overflow-visible sm:pb-0"
        >
          {sections.map((id) => {
            const meta = sectionMeta[id];
            const Icon = meta.icon;
            const active = section === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setSection(id)}
                className={cn(
                  "flex min-w-fit items-start gap-2.5 rounded-lg px-3 py-2.5 text-left transition-colors",
                  active
                    ? "bg-secondary text-foreground"
                    : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground",
                  id === "danger" &&
                    !active &&
                    "text-destructive/80 hover:text-destructive",
                )}
              >
                <Icon
                  className={cn(
                    "mt-0.5 size-4 shrink-0",
                    id === "danger" && "text-destructive",
                  )}
                />
                <span className="min-w-0">
                  <span className="block text-sm font-medium">
                    {meta.label}
                  </span>
                  <span className="text-muted-foreground hidden text-[11px] leading-snug sm:block">
                    {meta.description}
                  </span>
                </span>
              </button>
            );
          })}
        </nav>

        <div className="min-w-0 flex-1 space-y-4">
          {section === "general" ? (
            <SettingsPanel
              title="Organization profile"
              description="Basic identity and how machines join this organization."
              footer={
                isAdmin ? (
                  <Button
                    type="submit"
                    form="org-general-form"
                    disabled={loading}
                    size="sm"
                  >
                    {loading ? "Saving..." : "Save changes"}
                  </Button>
                ) : null
              }
            >
              <form
                id="org-general-form"
                className="space-y-5"
                onSubmit={(e) => void saveGeneral(e)}
              >
                <FieldBlock label="Organization name" htmlFor="org-name">
                  <Input
                    id="org-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    disabled={!isAdmin}
                  />
                </FieldBlock>
                <FieldBlock
                  label="Slug"
                  hint="Used in URLs and CLI references. Cannot be changed."
                >
                  <Input value={activeOrg?.slug ?? ""} disabled />
                </FieldBlock>
                <ToggleRow
                  id="quick-enroll"
                  label="Quick enroll"
                  description="Allow machines to join without a token. They stay pending until an admin approves."
                  checked={quickEnrollEnabled}
                  onCheckedChange={setQuickEnrollEnabled}
                  disabled={!isAdmin}
                />
              </form>
            </SettingsPanel>
          ) : null}

          {section === "machines" ? (
            <SettingsPanel
              title="Auto cleanup"
              description="Expire or remove machines that have not connected to the control plane for a while. Per-machine overrides still apply when this is off."
              footer={
                isAdmin ? (
                  <Button
                    type="submit"
                    form="org-machines-form"
                    disabled={orgSettingsMutations.update.isPending}
                    size="sm"
                  >
                    {orgSettingsMutations.update.isPending
                      ? "Saving..."
                      : "Save machine settings"}
                  </Button>
                ) : null
              }
            >
              {orgSettingsPending ? (
                <Skeleton className="h-40 w-full" />
              ) : (
                <form
                  id="org-machines-form"
                  className="space-y-5"
                  onSubmit={(e) => void saveMachineSettings(e)}
                >
                  <ToggleRow
                    id="auto-cleanup"
                    label="Enable auto cleanup"
                    description="Apply the org default inactivity policy to enrolled machines."
                    checked={cleanupEnabled}
                    onCheckedChange={setCleanupEnabled}
                    disabled={!isAdmin}
                  />

                  <div
                    className={cn(
                      "grid transition-[grid-template-rows,opacity] duration-200 ease-out",
                      cleanupEnabled
                        ? "grid-rows-[1fr] opacity-100"
                        : "grid-rows-[0fr] opacity-0",
                    )}
                  >
                    <div className="space-y-5 overflow-hidden">
                      <div className="border-border/70 space-y-5 border-t pt-5">
                        <FieldBlock
                          label="Inactivity period"
                          htmlFor="inactivity-after"
                          hint="Examples: 12h, 3d, 2w. Resets when the machine connects or heartbeats."
                        >
                          <Input
                            id="inactivity-after"
                            value={inactivityAfter}
                            onChange={(e) => setInactivityAfter(e.target.value)}
                            placeholder="7d"
                            disabled={!isAdmin}
                            className="max-w-xs"
                          />
                        </FieldBlock>

                        <div className="space-y-2.5">
                          <Label>When a machine expires</Label>
                          <div className="grid gap-2">
                            {cleanupModes.map((mode) => {
                              const selected = cleanupMode === mode.value;
                              return (
                                <button
                                  key={mode.value}
                                  type="button"
                                  disabled={!isAdmin}
                                  onClick={() => setCleanupMode(mode.value)}
                                  className={cn(
                                    "rounded-lg border px-3.5 py-3 text-left transition-colors",
                                    selected
                                      ? "border-foreground/25 bg-secondary/70 ring-1 ring-foreground/10"
                                      : "border-border/70 hover:bg-secondary/40",
                                    !isAdmin && "cursor-not-allowed opacity-60",
                                  )}
                                >
                                  <span className="block text-sm font-medium">
                                    {mode.title}
                                  </span>
                                  <span className="text-muted-foreground mt-0.5 block text-xs leading-relaxed">
                                    {mode.description}
                                  </span>
                                </button>
                              );
                            })}
                          </div>
                        </div>

                        <div
                          className={cn(
                            "grid transition-[grid-template-rows,opacity] duration-200 ease-out",
                            cleanupMode === "soft_then_hard"
                              ? "grid-rows-[1fr] opacity-100"
                              : "grid-rows-[0fr] opacity-0",
                          )}
                        >
                          <div className="overflow-hidden">
                            <FieldBlock
                              label="Hard-delete after soft expiry"
                              htmlFor="hard-delete-after"
                              hint="Grace period after soft expiry before the machine is permanently removed."
                            >
                              <Input
                                id="hard-delete-after"
                                value={hardDeleteAfter}
                                onChange={(e) =>
                                  setHardDeleteAfter(e.target.value)
                                }
                                placeholder="7d"
                                disabled={!isAdmin}
                                className="max-w-xs"
                              />
                            </FieldBlock>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </form>
              )}
            </SettingsPanel>
          ) : null}

          {section === "tunnels" ? (
            <SettingsPanel
              title="Tunnel defaults"
              description={
                <>
                  Point wildcard DNS{" "}
                  <span className="font-mono text-foreground/80">
                    *.your-domain
                  </span>{" "}
                  at the relay IP. Provide TLS via{" "}
                  <span className="font-mono text-foreground/80">
                    --cert/--key
                  </span>{" "}
                  or{" "}
                  <span className="font-mono text-foreground/80">
                    --acme-domain
                  </span>
                  .
                </>
              }
              footer={
                isAdmin ? (
                  <Button
                    type="submit"
                    form="org-tunnels-form"
                    disabled={settingsMutations.update.isPending}
                    size="sm"
                  >
                    {settingsMutations.update.isPending
                      ? "Saving..."
                      : "Save tunnel settings"}
                  </Button>
                ) : null
              }
            >
              {settingsPending ? (
                <Skeleton className="h-32 w-full" />
              ) : (
                <form
                  id="org-tunnels-form"
                  className="space-y-5"
                  onSubmit={(e) => void saveTunnelSettings(e)}
                >
                  <FieldBlock label="Default relay">
                    <Select
                      value={defaultRelayId}
                      onValueChange={(value) =>
                        setDefaultRelayId(value ?? "auto")
                      }
                      disabled={!isAdmin}
                    >
                      <SelectTrigger className="max-w-md">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="auto">
                          Auto (closest healthy)
                        </SelectItem>
                        {(relays ?? []).map((relay) => (
                          <SelectItem key={relay.id} value={relay.id}>
                            {relay.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FieldBlock>

                  <div className="grid gap-5 sm:grid-cols-2">
                    <FieldBlock
                      label="Default tunnel TTL (seconds)"
                      htmlFor="default-ttl"
                      hint="Leave empty for no expiry."
                    >
                      <Input
                        id="default-ttl"
                        type="number"
                        min={1}
                        placeholder="Never"
                        value={defaultTtl}
                        onChange={(e) => setDefaultTtl(e.target.value)}
                        disabled={!isAdmin}
                      />
                    </FieldBlock>
                    <FieldBlock
                      label="Max tunnels per machine"
                      htmlFor="max-tunnels"
                    >
                      <Input
                        id="max-tunnels"
                        type="number"
                        min={1}
                        max={1000}
                        value={maxTunnels}
                        onChange={(e) => setMaxTunnels(e.target.value)}
                        disabled={!isAdmin}
                      />
                    </FieldBlock>
                  </div>

                  <FieldBlock
                    label="Custom tunnel domain"
                    htmlFor="custom-domain"
                  >
                    <Input
                      id="custom-domain"
                      value={customDomain}
                      onChange={(e) => setCustomDomain(e.target.value)}
                      placeholder="tunnels.example.com"
                      disabled={!isAdmin}
                    />
                  </FieldBlock>

                  <FieldBlock
                    label="Peer DNS suffix"
                    htmlFor="peer-dns"
                    hint={
                      <>
                        Mesh hostnames resolve as{" "}
                        <span className="font-mono">
                          hostname.{peerDnsSuffix.trim() || "tuntun"}
                        </span>
                        .
                      </>
                    }
                  >
                    <Input
                      id="peer-dns"
                      value={peerDnsSuffix}
                      onChange={(e) => setPeerDnsSuffix(e.target.value)}
                      placeholder="tuntun"
                      disabled={!isAdmin}
                    />
                  </FieldBlock>

                  <div className="bg-muted/30 rounded-lg border border-border/70 px-4 py-3">
                    <p className="text-muted-foreground text-xs leading-relaxed">
                      Wildcard DNS should point{" "}
                      <span className="text-foreground font-mono">
                        *.
                        {customDomain.trim() ||
                          relays?.[0]?.domain ||
                          "relay.example.com"}
                      </span>{" "}
                      at your relay.
                    </p>
                  </div>
                </form>
              )}
            </SettingsPanel>
          ) : null}

          {section === "certificate" ? (
            <SettingsPanel
              title="Internal certificate authority"
              description="TunTun issues short-lived certificates from an organization CA when you create HTTPS serves. Agents trust this CA so peers can connect to mesh hostnames without public DNS."
              footer={
                isAdmin ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setRotateOpen(true)}
                  >
                    Rotate CA
                  </Button>
                ) : null
              }
            >
              {caPending ? (
                <Skeleton className="h-24 w-full" />
              ) : (
                <div className="space-y-5">
                  <div className="flex items-center gap-3">
                    <span className="text-muted-foreground text-sm">
                      Status
                    </span>
                    <EntityStatus
                      status={ca?.status ?? "missing"}
                      label={
                        ca?.status === "missing"
                          ? "Missing"
                          : ca?.status === "expired"
                            ? "Expired"
                            : undefined
                      }
                    />
                  </div>

                  {ca?.fingerprintSha256 ? (
                    <CopyField
                      label="Fingerprint (SHA-256)"
                      value={ca.fingerprintSha256}
                    />
                  ) : (
                    <p className="text-muted-foreground text-sm">
                      No CA issued yet. Creating a serve will provision one.
                    </p>
                  )}

                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="rounded-lg border border-border/70 px-3.5 py-3">
                      <p className="text-muted-foreground text-xs">
                        Not before
                      </p>
                      <p className="mt-1 text-sm">
                        {ca?.notBefore
                          ? new Date(ca.notBefore).toLocaleString()
                          : "—"}
                      </p>
                    </div>
                    <div className="rounded-lg border border-border/70 px-3.5 py-3">
                      <p className="text-muted-foreground text-xs">Not after</p>
                      <p className="mt-1 text-sm">
                        {ca?.notAfter
                          ? `${new Date(ca.notAfter).toLocaleString()} (${formatDistanceToNow(new Date(ca.notAfter), { addSuffix: true })})`
                          : "—"}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </SettingsPanel>
          ) : null}

          {section === "api-keys" ? (
            <SettingsPanel
              title="API keys"
              description="Programmatic access to the management API for this organization."
            >
              <ApiKeysPanel />
            </SettingsPanel>
          ) : null}

          {section === "sso" ? (
            <SettingsPanel
              title="Single sign-on"
              description="Register an external OIDC identity provider for this organization. Dashboard login and SSH check-mode re-auth use Better Auth SSO."
              footer={
                isAdmin ? (
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="submit"
                      form="org-sso-form"
                      disabled={ssoMutations.upsert.isPending}
                      size="sm"
                    >
                      {ssoMutations.upsert.isPending
                        ? "Saving..."
                        : ssoProvider
                          ? "Update SSO provider"
                          : "Register SSO provider"}
                    </Button>
                    {ssoProvider ? (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => setRemoveSsoOpen(true)}
                        disabled={ssoMutations.remove.isPending}
                      >
                        Remove
                      </Button>
                    ) : null}
                  </div>
                ) : null
              }
            >
              {ssoPending ? (
                <Skeleton className="h-40 w-full" />
              ) : (
                <form
                  id="org-sso-form"
                  className="space-y-5"
                  onSubmit={(e) => void saveSsoSettings(e)}
                >
                  {ssoProvider ? (
                    <p className="text-muted-foreground text-xs">
                      Provider ID:{" "}
                      <code className="text-foreground">
                        {ssoProvider.providerId}
                      </code>
                    </p>
                  ) : null}

                  <FieldBlock label="Email domain" htmlFor="sso-domain">
                    <Input
                      id="sso-domain"
                      value={ssoDomain}
                      onChange={(e) => setSsoDomain(e.target.value)}
                      placeholder="company.com"
                      disabled={!isAdmin}
                      required
                    />
                  </FieldBlock>

                  <FieldBlock label="Issuer URL" htmlFor="issuer-url">
                    <Input
                      id="issuer-url"
                      value={issuerUrl}
                      onChange={(e) => setIssuerUrl(e.target.value)}
                      placeholder="https://accounts.example.com"
                      disabled={!isAdmin}
                      required
                    />
                  </FieldBlock>

                  <div className="grid gap-5 sm:grid-cols-2">
                    <FieldBlock label="Client ID" htmlFor="client-id">
                      <Input
                        id="client-id"
                        value={clientId}
                        onChange={(e) => setClientId(e.target.value)}
                        disabled={!isAdmin}
                        required
                      />
                    </FieldBlock>
                    <FieldBlock label="Client secret" htmlFor="client-secret">
                      <Input
                        id="client-secret"
                        type="password"
                        value={clientSecret}
                        onChange={(e) => setClientSecret(e.target.value)}
                        placeholder={
                          ssoProvider?.clientSecretSet
                            ? "Leave blank to keep current"
                            : "Secret"
                        }
                        disabled={!isAdmin}
                        autoComplete="new-password"
                        required={!ssoProvider?.clientSecretSet}
                      />
                    </FieldBlock>
                  </div>

                  <FieldBlock
                    label="Discovery URL (optional)"
                    htmlFor="discovery-url"
                    hint="Defaults to /.well-known/openid-configuration on the issuer."
                  >
                    <Input
                      id="discovery-url"
                      value={discoveryUrl}
                      onChange={(e) => setDiscoveryUrl(e.target.value)}
                      placeholder="Defaults to /.well-known/openid-configuration"
                      disabled={!isAdmin}
                    />
                  </FieldBlock>

                  <FieldBlock label="Scopes" htmlFor="sso-scopes">
                    <Input
                      id="sso-scopes"
                      value={scopes}
                      onChange={(e) => setScopes(e.target.value)}
                      disabled={!isAdmin}
                    />
                  </FieldBlock>
                </form>
              )}
            </SettingsPanel>
          ) : null}

          {section === "danger" && isOwner ? (
            <SettingsPanel
              title="Delete organization"
              description="This permanently removes all networks, machines, members, and settings. This cannot be undone."
            >
              <div className="border-destructive/25 bg-destructive/5 space-y-4 rounded-lg border px-4 py-4">
                {!deleteOpen ? (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => setDeleteOpen(true)}
                  >
                    Delete organization
                  </Button>
                ) : (
                  <div className="space-y-3">
                    <p className="text-sm">
                      Type <strong>{activeOrg?.name}</strong> to confirm.
                    </p>
                    <Input
                      placeholder={activeOrg?.name}
                      value={deleteConfirm}
                      onChange={(e) => setDeleteConfirm(e.target.value)}
                      className="max-w-sm"
                    />
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setDeleteOpen(false);
                          setDeleteConfirm("");
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={deleteConfirm !== activeOrg?.name}
                        onClick={() => void deleteOrg()}
                      >
                        Delete organization
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            </SettingsPanel>
          ) : null}
        </div>
      </div>

      <ConfirmDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        title="Rotate internal CA"
        description="Rotating the CA invalidates all existing serve certificates. Agents will need fresh certs on next serve start."
        confirmLabel="Rotate CA"
        destructive
        loading={caMutations.rotate.isPending}
        onConfirm={async () => {
          try {
            await caMutations.rotate.mutateAsync();
            toast.success("Internal CA rotated");
            setRotateOpen(false);
          } catch (err) {
            toast.error(
              err instanceof Error ? err.message : "Failed to rotate CA",
            );
          }
        }}
      />

      <ConfirmDialog
        open={removeSsoOpen}
        onOpenChange={setRemoveSsoOpen}
        title="Remove SSO provider"
        description="SSH check-mode will fall back to TunTun session authentication. Dashboard SSO login for this org domain will stop working."
        confirmLabel="Remove SSO"
        destructive
        loading={ssoMutations.remove.isPending}
        onConfirm={() => void removeSsoSettings()}
      />
    </>
  );
}
