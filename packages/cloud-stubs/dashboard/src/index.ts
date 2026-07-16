import type { ReactNode } from "react";

/**
 * Community / OSS stub: no marketing landing. The app route handles redirect.
 */
export function HomePage(): ReactNode {
  return null;
}

/** When false, `/` should redirect into the app (login or /app). */
export const hasMarketingLanding = false;
