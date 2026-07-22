import { useMemo } from "react";
import {
  Combobox,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
  ComboboxPopup,
} from "@/components/ui/combobox";
import type { AggregatedMachine } from "@/lib/machine-utils";
import { useMachines } from "@/lib/queries/management";
import { cn } from "@/lib/utils";

export function shortEndpointId(id: string): string {
  return id.length <= 10 ? id : `${id.slice(0, 6)}…${id.slice(-4)}`;
}

type EndpointOption = {
  value: string;
  label: string;
  name: string;
  networkName: string;
  shortId: string;
};

function toOption(machine: AggregatedMachine): EndpointOption {
  const shortId = shortEndpointId(machine.endpointId);
  return {
    value: machine.endpointId,
    label: `${machine.name} (${machine.networkName}) · ${shortId}`,
    name: machine.name,
    networkName: machine.networkName,
    shortId,
  };
}

function useEndpointOptions(
  orgId: string | undefined,
  networkId: string | undefined,
  selectedId: string,
): EndpointOption[] {
  const { data: machines } = useMachines(orgId);
  return useMemo(() => {
    const list = (machines ?? []).filter((m) =>
      networkId ? m.networkId === networkId : true,
    );
    const options = list.map(toOption);
    if (
      selectedId &&
      !options.some((o) => o.value.toLowerCase() === selectedId.toLowerCase())
    ) {
      options.unshift({
        value: selectedId,
        label: shortEndpointId(selectedId),
        name: selectedId,
        networkName: "",
        shortId: shortEndpointId(selectedId),
      });
    }
    return options.sort((a, b) => a.label.localeCompare(b.label));
  }, [machines, networkId, selectedId]);
}

export function EndpointCombobox({
  orgId,
  networkId,
  value,
  onValueChange,
  placeholder = "Search machines…",
  disabled,
  className,
  id,
}: {
  orgId: string | undefined;
  networkId?: string;
  value: string;
  onValueChange: (endpointId: string) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  id?: string;
}) {
  const selectedId = value.trim();
  const items = useEndpointOptions(orgId, networkId, selectedId);
  const selected =
    items.find((o) => o.value.toLowerCase() === selectedId.toLowerCase()) ??
    null;

  return (
    <Combobox
      items={items}
      value={selected}
      onValueChange={(next) => {
        onValueChange(next?.value ?? "");
      }}
      itemToStringLabel={(item) => item.label}
      disabled={disabled}
    >
      <ComboboxInput
        id={id}
        className={cn("w-full", className)}
        placeholder={placeholder}
        showClear={Boolean(selected)}
        disabled={disabled}
      />
      <ComboboxPopup>
        <ComboboxEmpty>
          {items.length === 0 ? "No machines found." : "No matching machines."}
        </ComboboxEmpty>
        <ComboboxList>
          {(item: EndpointOption) => (
            <ComboboxItem key={item.value} value={item}>
              <span className="flex min-w-0 flex-col gap-0.5">
                <span className="truncate font-medium">{item.name}</span>
                <span className="text-muted-foreground truncate text-xs">
                  {item.networkName
                    ? `${item.networkName} · ${item.shortId}`
                    : item.shortId}
                </span>
              </span>
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxPopup>
    </Combobox>
  );
}
