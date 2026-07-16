import { useQueryClient } from "@tanstack/react-query";
import { CheckIcon, ChevronsUpDownIcon, PlusIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { CreateOrganizationDialog } from "@/components/app/create-organization-dialog";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { useEntitlements } from "@/hooks/use-entitlements";
import {
  authClient,
  useActiveOrganization,
  useListOrganizations,
} from "@/lib/auth-client";
import { queryKeys } from "@/lib/query-keys";
import { cn } from "@/lib/utils";

export function OrgSwitcher() {
  const [open, setOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const queryClient = useQueryClient();
  const { data: organizations, isPending } = useListOrganizations();
  const { data: activeOrganization } = useActiveOrganization();
  const { data: entitlements } = useEntitlements();
  const multiOrg = entitlements?.multiOrganization ?? false;

  async function switchOrg(organizationId: string) {
    const { error } = await authClient.organization.setActive({
      organizationId,
    });
    if (error) {
      toast.error(error.message ?? "Failed to switch organization");
      return;
    }
    void queryClient.invalidateQueries();
    if (activeOrganization?.id) {
      void queryClient.removeQueries({
        queryKey: queryKeys.org(activeOrganization.id),
      });
    }
    setOpen(false);
    toast.success("Organization switched");
  }

  if (!multiOrg) {
    return (
      <span className="truncate px-2 text-sm font-medium">
        {isPending
          ? "Loading..."
          : (activeOrganization?.name ?? "Organization")}
      </span>
    );
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={
          <Button
            variant="ghost"
            role="combobox"
            aria-expanded={open}
            className="h-9 max-w-[220px] justify-between px-2 font-medium"
          />
        }
      >
        <span className="truncate">
          {isPending
            ? "Loading..."
            : (activeOrganization?.name ?? "Select organization")}
        </span>
        <ChevronsUpDownIcon className="ml-2 size-4 shrink-0 opacity-50" />
      </PopoverTrigger>
      <PopoverContent className="w-[260px] p-0" align="start">
        <Command>
          <CommandInput placeholder="Search organizations..." />
          <CommandList>
            <CommandEmpty>No organizations found.</CommandEmpty>
            <CommandGroup heading="Organizations">
              {(organizations ?? []).map((org) => (
                <CommandItem
                  key={org.id}
                  value={org.name}
                  onSelect={() => void switchOrg(org.id)}
                >
                  <CheckIcon
                    className={cn(
                      "mr-2 size-4",
                      activeOrganization?.id === org.id
                        ? "opacity-100"
                        : "opacity-0",
                    )}
                  />
                  {org.name}
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandSeparator />
            <CommandGroup>
              <CommandItem
                onSelect={() => {
                  setOpen(false);
                  setCreateOpen(true);
                }}
              >
                <PlusIcon className="mr-2 size-4" />
                Create organization
              </CommandItem>
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
      <CreateOrganizationDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
      />
    </Popover>
  );
}
