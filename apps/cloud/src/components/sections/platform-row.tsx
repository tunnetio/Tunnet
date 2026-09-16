import { Marquee } from "@tunnet/ui/components/marquee";
import type { ReactNode } from "react";
import {
  FaApple,
  FaAws,
  FaDocker,
  FaGithub,
  FaLinux,
  FaWindows,
} from "react-icons/fa";
import { SiKubernetes, SiTerraform } from "react-icons/si";

const PLATFORMS = [
  { icon: FaApple, label: "macOS" },
  { icon: FaLinux, label: "Linux" },
  { icon: FaWindows, label: "Windows" },
  { icon: FaDocker, label: "Docker" },
  { icon: SiKubernetes, label: "Kubernetes" },
  { icon: FaGithub, label: "GitHub Actions" },
  { icon: SiTerraform, label: "Terraform" },
  { icon: FaAws, label: "AWS" },
] as const;

export function PlatformRow(): ReactNode {
  return (
    <section className="py-4">
      <p className="mb-5 text-center text-[12px] tracking-[0.14em] text-[var(--l1-muted-2)] uppercase">
        Runs where you already work
      </p>
      <Marquee pauseOnHover className="[--duration:36s]">
        {PLATFORMS.map(({ icon: Icon, label }) => (
          <span
            key={label}
            className="mx-6 inline-flex items-center gap-2 text-[13px] text-[var(--l1-muted)]"
          >
            <Icon className="size-4" />
            {label}
          </span>
        ))}
      </Marquee>
    </section>
  );
}
