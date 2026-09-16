import { type ReactNode, useEffect } from "react";
import "@/marketing.css";
import { MarketingFooter } from "#/components/footer";
import { initSmoothScroll } from "#/components/motion/smooth-scroll";
import { MarketingNav } from "#/components/nav";
import { AudienceQuotesSection } from "#/components/sections/audience-quotes";
import { CapabilityBand } from "#/components/sections/capability-band";
import { ControlPlaneSection } from "#/components/sections/control-plane";
import { FaqSection } from "#/components/sections/faq";
import { IdentityPathsSection } from "#/components/sections/identity-paths";
import { OpenSourceSection } from "#/components/sections/open-source";
import { PlatformRow } from "#/components/sections/platform-row";
import { ProductStage } from "#/components/sections/product-stage";
import { TwoModesSection } from "#/components/sections/two-modes";

export function HomePage(): ReactNode {
  useEffect(() => {
    const cleanup = initSmoothScroll();
    return cleanup;
  }, []);

  return (
    <div className="marketing-root relative min-h-svh bg-[var(--l1-bg)] text-[var(--l1-fg)]">
      <MarketingNav />
      <main className="overflow-x-hidden">
        <ProductStage />
        <PlatformRow />
        <ControlPlaneSection />
        <IdentityPathsSection />
        <CapabilityBand />
        <TwoModesSection />
        <OpenSourceSection />
        <AudienceQuotesSection />
        <FaqSection />
      </main>
      <MarketingFooter />
    </div>
  );
}
