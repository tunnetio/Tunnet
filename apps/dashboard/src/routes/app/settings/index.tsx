import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AuthorizeCliDialog } from "@/components/app/device-authorize";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { authClient, signOut, useSession } from "@/lib/auth-client";

export const Route = createFileRoute("/app/settings/")({
  validateSearch: (search: Record<string, unknown>) => ({
    user_code:
      typeof search.user_code === "string" ? search.user_code : undefined,
  }),
  component: UserSettingsPage,
});

function UserSettingsPage() {
  const navigate = useNavigate();
  const { user_code: userCodeFromUrl } = Route.useSearch();
  const { data: session } = useSession();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [cliOpen, setCliOpen] = useState(Boolean(userCodeFromUrl));
  const [cliInitialCode, setCliInitialCode] = useState(userCodeFromUrl);

  useEffect(() => {
    if (!userCodeFromUrl) return;
    setCliInitialCode(userCodeFromUrl);
    setCliOpen(true);
  }, [userCodeFromUrl]);

  function handleCliOpenChange(open: boolean) {
    setCliOpen(open);
    if (!open && userCodeFromUrl) {
      setCliInitialCode(undefined);
      void navigate({
        to: "/app/settings",
        search: { user_code: undefined },
        replace: true,
      });
    }
  }

  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    const { error } = await authClient.changePassword({
      currentPassword,
      newPassword,
      revokeOtherSessions: false,
    });
    setLoading(false);
    if (error) {
      toast.error(error.message ?? "Failed to change password");
      return;
    }
    toast.success("Password updated");
    setCurrentPassword("");
    setNewPassword("");
  }

  async function handleSignOut() {
    await signOut({
      fetchOptions: {
        onSuccess: () => {
          window.location.href = "/login";
        },
      },
    });
  }

  return (
    <>
      <PageHeader
        title="Settings"
        description="Manage your personal account."
      />

      <div className="max-w-2xl space-y-4">
        <section className="overflow-hidden rounded-xl border border-border/80 bg-card">
          <div className="border-b border-border/70 px-5 py-4 sm:px-6">
            <h2 className="text-sm font-semibold tracking-tight">Profile</h2>
            <p className="text-muted-foreground mt-1 text-sm">
              Details from your TunTun account.
            </p>
          </div>
          <div className="divide-y divide-border/70 px-5 sm:px-6">
            <div className="flex items-center justify-between gap-4 py-3.5 text-sm">
              <span className="text-muted-foreground">Name</span>
              <span className="font-medium">{session?.user.name}</span>
            </div>
            <div className="flex items-center justify-between gap-4 py-3.5 text-sm">
              <span className="text-muted-foreground">Email</span>
              <span className="font-medium">{session?.user.email}</span>
            </div>
          </div>
        </section>

        <section className="overflow-hidden rounded-xl border border-border/80 bg-card">
          <div className="border-b border-border/70 px-5 py-4 sm:px-6">
            <h2 className="text-sm font-semibold tracking-tight">CLI access</h2>
            <p className="text-muted-foreground mt-1 text-sm">
              Link the TunTun CLI to this account with a device code from{" "}
              <code className="text-foreground">tuntun login</code>.
            </p>
          </div>
          <div className="px-5 py-4 sm:px-6">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setCliInitialCode(undefined);
                setCliOpen(true);
              }}
            >
              Authorize CLI
            </Button>
          </div>
        </section>

        <section className="overflow-hidden rounded-xl border border-border/80 bg-card">
          <div className="border-b border-border/70 px-5 py-4 sm:px-6">
            <h2 className="text-sm font-semibold tracking-tight">
              Change password
            </h2>
          </div>
          <div className="px-5 py-5 sm:px-6">
            <form
              className="max-w-md space-y-4"
              onSubmit={(e) => void changePassword(e)}
            >
              <div className="space-y-2">
                <Label htmlFor="current-password">Current password</Label>
                <Input
                  id="current-password"
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">New password</Label>
                <Input
                  id="new-password"
                  type="password"
                  minLength={8}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
              </div>
              <Button type="submit" size="sm" disabled={loading}>
                {loading ? "Updating..." : "Update password"}
              </Button>
            </form>
          </div>
        </section>

        <section className="overflow-hidden rounded-xl border border-border/80 bg-card">
          <div className="border-b border-border/70 px-5 py-4 sm:px-6">
            <h2 className="text-sm font-semibold tracking-tight">Session</h2>
          </div>
          <div className="px-5 py-4 sm:px-6">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleSignOut()}
            >
              Sign out
            </Button>
          </div>
        </section>
      </div>

      <AuthorizeCliDialog
        open={cliOpen}
        onOpenChange={handleCliOpenChange}
        initialCode={cliInitialCode}
      />
    </>
  );
}
