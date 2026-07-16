import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useEntitlements } from "@/hooks/use-entitlements";
import { getEntitlements, getSession } from "@/lib/auth.functions";
import { authClient, signIn, signUp } from "@/lib/auth-client";

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>) => ({
    redirect: typeof search.redirect === "string" ? search.redirect : undefined,
  }),
  beforeLoad: async ({ search }) => {
    const session = await getSession();
    if (!session) {
      const entitlements = await getEntitlements();
      return { entitlements };
    }
    if (search.redirect?.startsWith("/")) {
      throw redirect({ href: search.redirect });
    }
    throw redirect({ to: "/app" });
  },
  component: LoginPage,
});

function LoginPage() {
  const navigate = useNavigate();
  const { redirect: redirectTo } = Route.useSearch();
  const routeEntitlements = Route.useRouteContext({
    select: (ctx) =>
      "entitlements" in ctx
        ? (
            ctx as {
              entitlements?: { openSignUp?: boolean };
            }
          ).entitlements
        : undefined,
  });
  const { data: liveEntitlements } = useEntitlements();
  const entitlements = liveEntitlements ?? routeEntitlements;
  const showSignup = Boolean(entitlements?.openSignUp);

  const [loading, setLoading] = useState(false);
  const [ssoLoading, setSsoLoading] = useState(false);

  async function afterAuth() {
    if (redirectTo) {
      window.location.href = redirectTo;
      return;
    }
    void navigate({ to: "/app" });
  }

  async function handleSignIn(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setLoading(true);
    const { error } = await signIn.email({
      email: String(form.get("email")),
      password: String(form.get("password")),
    });
    setLoading(false);
    if (error) {
      toast.error(error.message ?? "Sign in failed");
      return;
    }
    await afterAuth();
  }

  async function handleSignUp(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setLoading(true);
    const { error } = await signUp.email({
      name: String(form.get("name")),
      email: String(form.get("email")),
      password: String(form.get("password")),
    });
    setLoading(false);
    if (error) {
      toast.error(error.message ?? "Registration failed");
      return;
    }
    await afterAuth();
  }

  async function handleSso(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const email = String(form.get("sso-email") ?? "").trim();
    const domain = String(form.get("sso-domain") ?? "").trim();
    if (!email && !domain) {
      toast.error("Enter an email or domain for SSO");
      return;
    }
    setSsoLoading(true);
    const { error, data } = await authClient.signIn.sso({
      ...(email ? { email } : {}),
      ...(domain ? { domain } : {}),
      callbackURL: redirectTo || `${window.location.origin}/app`,
    });
    setSsoLoading(false);
    if (error) {
      toast.error(error.message ?? "SSO sign-in failed");
      return;
    }
    if (data && typeof data === "object" && "url" in data && data.url) {
      window.location.href = String(data.url);
    }
  }

  const tabCount = showSignup ? 3 : 2;

  return (
    <div className="bg-background flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>TunTun</CardTitle>
          <CardDescription>
            Sign in to manage your networks and machines.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="signin">
            <TabsList
              className="grid w-full"
              style={{
                gridTemplateColumns: `repeat(${tabCount}, minmax(0, 1fr))`,
              }}
            >
              <TabsTrigger value="signin">Sign in</TabsTrigger>
              <TabsTrigger value="sso">SSO</TabsTrigger>
              {showSignup ? (
                <TabsTrigger value="signup">Create</TabsTrigger>
              ) : null}
            </TabsList>
            <TabsContent value="signin">
              <form
                className="space-y-4 pt-2"
                onSubmit={(e) => void handleSignIn(e)}
              >
                <div className="space-y-2">
                  <Label htmlFor="signin-email">Email</Label>
                  <Input
                    id="signin-email"
                    name="email"
                    type="email"
                    required
                    autoComplete="email"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="signin-password">Password</Label>
                  <Input
                    id="signin-password"
                    name="password"
                    type="password"
                    required
                    autoComplete="current-password"
                  />
                </div>
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? "Signing in..." : "Sign in"}
                </Button>
              </form>
            </TabsContent>
            <TabsContent value="sso">
              <form
                className="space-y-4 pt-2"
                onSubmit={(e) => void handleSso(e)}
              >
                <p className="text-muted-foreground text-sm">
                  Sign in with your organization&apos;s identity provider.
                </p>
                <div className="space-y-2">
                  <Label htmlFor="sso-email">Work email</Label>
                  <Input
                    id="sso-email"
                    name="sso-email"
                    type="email"
                    autoComplete="email"
                    placeholder="you@company.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="sso-domain">Or domain</Label>
                  <Input
                    id="sso-domain"
                    name="sso-domain"
                    placeholder="company.com"
                  />
                </div>
                <Button type="submit" className="w-full" disabled={ssoLoading}>
                  {ssoLoading ? "Redirecting..." : "Continue with SSO"}
                </Button>
              </form>
            </TabsContent>
            {showSignup ? (
              <TabsContent value="signup">
                <form
                  className="space-y-4 pt-2"
                  onSubmit={(e) => void handleSignUp(e)}
                >
                  <div className="space-y-2">
                    <Label htmlFor="signup-name">Name</Label>
                    <Input
                      id="signup-name"
                      name="name"
                      required
                      autoComplete="name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="signup-email">Email</Label>
                    <Input
                      id="signup-email"
                      name="email"
                      type="email"
                      required
                      autoComplete="email"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="signup-password">Password</Label>
                    <Input
                      id="signup-password"
                      name="password"
                      type="password"
                      required
                      minLength={8}
                      autoComplete="new-password"
                    />
                  </div>
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? "Creating account..." : "Create account"}
                  </Button>
                </form>
              </TabsContent>
            ) : null}
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
