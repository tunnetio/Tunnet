import { type ReactNode, useEffect } from "react";
import "@/marketing.css";
import { MarketingFooter } from "#/components/footer";
import { initSmoothScroll } from "#/components/motion/smooth-scroll";
import { MarketingNav } from "#/components/nav";
import { Calculator } from "#/components/pricing/calculator";
import { Comparison } from "#/components/pricing/comparison";
import { PlanCards } from "#/components/pricing/plan-cards";
import { PricingFaq } from "#/components/pricing/pricing-faq";
import { PricingHero } from "#/components/pricing/pricing-hero";
import { FinalCtaSection } from "#/components/sections/final-cta";

export function PricingPage(): ReactNode {
  useEffect(() => {
    const cleanup = initSmoothScroll();
    return cleanup;
  }, []);

  return (
    <div className="marketing-root relative min-h-svh bg-[var(--l1-bg)] text-[var(--l1-fg)]">
      <MarketingNav />
      <main className="overflow-x-hidden">
        <PricingHero />
        <PlanCards />
        <Calculator />
        <Comparison />
        <PricingFaq />
        <FinalCtaSection />
      </main>
      <MarketingFooter />
    </div>
  );
}
