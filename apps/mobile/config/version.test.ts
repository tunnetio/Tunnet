import { describe, expect, test } from "bun:test";

import {
  cargoWorkspaceVersion,
  resolveAppVersion,
  versionCodeOf,
} from "./version.js";

describe("app version resolution", () => {
  test("reads the workspace package version", () => {
    const cargo = [
      "[workspace]",
      'members = ["crates/*"]',
      "",
      "[workspace.package]",
      'version = "0.9.1"',
      'edition = "2024"',
    ].join("\n");

    expect(cargoWorkspaceVersion(cargo)).toBe("0.9.1");
  });

  test("uses Cargo as the deterministic default and encodes the Android code", () => {
    expect(resolveAppVersion({ cargoVersion: "0.9.1" })).toEqual({
      version: "0.9.1",
      versionCode: 901,
    });
  });

  test("allows an injected release version with a tag prefix", () => {
    expect(
      resolveAppVersion({ injected: "v1.2.3", cargoVersion: "0.9.1" }),
    ).toEqual({
      version: "1.2.3",
      versionCode: 10203,
    });
  });

  test("rejects versions that cannot be sequenced", () => {
    expect(() => versionCodeOf("0.100.0")).toThrow("at most 99");
    expect(() =>
      resolveAppVersion({
        injected: "desktop-v0.2.1-59-gbeb2baa",
        cargoVersion: "0.9.1",
      }),
    ).toThrow("exact major.minor.patch");
  });
});
