export type ResolvedAppVersion = {
  version: string;
  versionCode: number;
};

export function cargoWorkspaceVersion(contents: string): string;
export function resolveAppVersion(options: {
  injected?: string;
  cargoVersion: string;
}): ResolvedAppVersion;
export function stripTagPrefix(version: string): string;
export function versionCodeOf(version: string): number;
