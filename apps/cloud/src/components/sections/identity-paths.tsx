"use client";

import { GoogleGeminiEffect } from "@tunnet/ui/components/ui/google-gemini-effect";
import { useScroll, useTransform } from "motion/react";
import { type ReactNode, useRef } from "react";

const APP_URL = "https://app.tunnet.io";

export function IdentityPathsSection(): ReactNode {
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start end", "end start"],
  });
  const pathLengthFirst = useTransform(scrollYProgress, [0, 1], [0.45, 1.15]);
  const pathLengthSecond = useTransform(scrollYProgress, [0, 1], [0.4, 1.15]);
  const pathLengthThird = useTransform(scrollYProgress, [0, 1], [0.35, 1.15]);
  const pathLengthFourth = useTransform(scrollYProgress, [0, 1], [0.3, 1.15]);
  const pathLengthFifth = useTransform(scrollYProgress, [0, 1], [0.25, 1.15]);

  return (
    <section
      ref={ref}
      className="relative overflow-x-hidden px-4 py-16 sm:px-6 sm:py-24"
    >
      <GoogleGeminiEffect
        title="One identity. Every job."
        description="Private access, SSH, internal apps, and public HTTPS - one identity, not four products stitched together."
        pathLengths={[
          pathLengthFirst,
          pathLengthSecond,
          pathLengthThird,
          pathLengthFourth,
          pathLengthFifth,
        ]}
        cta={
          <a href={APP_URL} className="l1-btn l1-btn--copper">
            Start for free
          </a>
        }
      />
    </section>
  );
}
