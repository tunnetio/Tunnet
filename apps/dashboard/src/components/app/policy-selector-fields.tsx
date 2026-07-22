import type { CreatePolicyBody, Selector } from "@tunnet/api/management";
import { EndpointCombobox } from "@/components/app/endpoint-combobox";
import { TagCombobox } from "@/components/app/tag-combobox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function PolicySelectorFields({
  orgId,
  networkId,
  label,
  kind,
  value,
  onKindChange,
  onValueChange,
}: {
  orgId?: string;
  networkId?: string;
  label: string;
  kind: string;
  value: string;
  onKindChange: (kind: string) => void;
  onValueChange: (value: string) => void;
}) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <div className="flex gap-2">
        <Select
          value={kind}
          onValueChange={(v) => {
            if (v != null) onKindChange(v);
          }}
        >
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">Any</SelectItem>
            <SelectItem value="tag">Tag</SelectItem>
            <SelectItem value="endpoint">Endpoint</SelectItem>
            <SelectItem value="cidr">CIDR</SelectItem>
            <SelectItem value="network">Network</SelectItem>
            <SelectItem value="user">User</SelectItem>
          </SelectContent>
        </Select>
        {kind === "tag" ? (
          <TagCombobox
            orgId={orgId}
            value={value}
            onValueChange={onValueChange}
            placeholder="Search tags…"
            className="flex-1"
          />
        ) : kind === "endpoint" ? (
          <EndpointCombobox
            orgId={orgId}
            networkId={networkId}
            value={value}
            onValueChange={onValueChange}
            placeholder="Search machines…"
            className="flex-1"
          />
        ) : kind !== "any" ? (
          <Input
            value={value}
            onChange={(e) => onValueChange(e.target.value)}
            placeholder={selectorPlaceholder(kind)}
            required
            className="flex-1"
          />
        ) : null}
      </div>
    </div>
  );
}

function selectorPlaceholder(kind: string): string {
  switch (kind) {
    case "cidr":
      return "10.0.0.0/8";
    case "tag":
      return "production";
    case "user":
      return "alice@company.com";
    case "network":
      return "network name";
    default:
      return "endpoint id";
  }
}

export function selectorKind(selector: Selector): string {
  return selector.kind;
}

export function selectorValue(selector: Selector): string {
  if (selector.kind === "any") return "";
  return selector.value;
}

export function buildSelector(kind: string, value: string): Selector {
  if (kind === "any") return { kind: "any" };
  if (kind === "tag") return { kind: "tag", value };
  if (kind === "endpoint") return { kind: "endpoint", value };
  if (kind === "network") return { kind: "network", value };
  if (kind === "user") return { kind: "user", value };
  return { kind: "cidr", value };
}

export function buildPolicySelector(kind: string, value: string): Selector {
  return buildSelector(kind, value);
}

export function formatPolicySelector(selector: Selector): string {
  if (selector.kind === "any") return "any";
  return `${selector.kind}:${selector.value}`;
}

/** Shared optional fields for create-policy forms. */
export type PolicyExtraFields = {
  slug: string;
  srcPosture: string;
};

export function applyPolicyExtraFields(
  body: CreatePolicyBody,
  extra: PolicyExtraFields,
): CreatePolicyBody {
  const slug = extra.slug.trim();
  const posture = extra.srcPosture
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return {
    ...body,
    ...(slug ? { slug } : {}),
    ...(posture.length > 0 ? { srcPosture: posture } : {}),
  };
}
