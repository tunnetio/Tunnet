import { createFileRoute, redirect } from "@tanstack/react-router";

/** Old approve links → user settings (CLI authorize dialog). */
export const Route = createFileRoute("/device/approve")({
  validateSearch: (search: Record<string, unknown>) => ({
    user_code:
      typeof search.user_code === "string" ? search.user_code : undefined,
  }),
  beforeLoad: async ({ search }) => {
    throw redirect({
      to: "/app/settings",
      search: search.user_code
        ? { user_code: search.user_code }
        : { user_code: undefined },
    });
  },
});
