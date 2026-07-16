/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly DASHBOARD_URL?: string;
  readonly MANAGEMENT_URL?: string;
  readonly CONTROL_PLANE_URL?: string;
  readonly TUNTUN_DEPLOYMENT?: string;
  readonly TUNTUN_LICENSE_TIER?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
