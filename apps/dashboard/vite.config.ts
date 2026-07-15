import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import { devtools } from "@tanstack/devtools-vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import { getManagementUrl } from "@tuntun/env";

import viteReact from "@vitejs/plugin-react";
import { nitro } from "nitro/vite";
import { defineConfig } from "vite";

const managementApiUrl = getManagementUrl();

const config = defineConfig({
  envDir: path.resolve(import.meta.dirname, "../.."),
  envPrefix: ["VITE_", "DASHBOARD_", "MANAGEMENT_", "CONTROL_PLANE_"],
  resolve: { tsconfigPaths: true },
  preview: {
    port: 5173,
  },
  plugins: [
    devtools(),
    nitro({
      rollupConfig: { external: [/^@sentry\//] },
      ...(managementApiUrl
        ? {
            routeRules: {
              "/api/**": { proxy: `${managementApiUrl}/api/**` },
              "/.well-known/**": {
                proxy: `${managementApiUrl}/.well-known/**`,
              },
              "/auth/**": { proxy: `${managementApiUrl}/auth/**` },
            },
          }
        : {}),
    }),
    tailwindcss(),
    tanstackStart(),
    viteReact(),
  ],
});

export default config;
