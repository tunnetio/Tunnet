/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly DASHBOARD_URL?: string;
  readonly MANAGEMENT_URL?: string;
  readonly CONTROL_PLANE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
