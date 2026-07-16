import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { getSession } from "@/lib/auth.functions";
import { authClient } from "@/lib/auth-client";

export const Route = createFileRoute("/accept-invitation/$invitationId")({
  component: AcceptInvitationPage,
});

function AcceptInvitationPage() {
  const { invitationId } = Route.useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [needsLogin, setNeedsLogin] = useState(false);

  useEffect(() => {
    void (async () => {
      const session = await getSession();
      if (!session) {
        setNeedsLogin(true);
        setLoading(false);
        return;
      }

      const { data, error } = await authClient.organization.acceptInvitation({
        invitationId,
      });

      if (error) {
        toast.error(error.message ?? "Failed to accept invitation");
        setLoading(false);
        return;
      }

      if (data?.organizationId) {
        await authClient.organization.setActive({
          organizationId: data.organizationId,
        });
      }

      toast.success("Invitation accepted");
      void navigate({ to: "/app" });
    })();
  }, [invitationId, navigate]);

  if (loading && !needsLogin) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle>Accepting invitation...</CardTitle>
          </CardHeader>
        </Card>
      </div>
    );
  }

  if (needsLogin) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle>Sign in required</CardTitle>
            <CardDescription>
              Sign in or create an account with the invited email, then return
              here to join the organization.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              className="w-full"
              onClick={() => {
                window.location.href = `/login?redirect=${encodeURIComponent(window.location.pathname)}`;
              }}
            >
              Go to sign in
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return null;
}
