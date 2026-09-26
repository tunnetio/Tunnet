const semanticVersionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const cargoVersionLine = /^\s*version\s*=\s*"([^"]+)"/;

function cargoWorkspaceVersion(contents) {
  const lines = contents.split(/\r?\n/);
  const start = lines.findIndex(
    (line) => line.trim() === "[workspace.package]",
  );

  if (start < 0) {
    throw new Error("Cargo.toml does not contain [workspace.package].");
  }

  for (const line of lines.slice(start + 1)) {
    if (line.trim().startsWith("[")) break;

    const match = line.match(cargoVersionLine);
    if (match?.[1]) return match[1];
  }

  throw new Error("Cargo.toml [workspace.package] does not define version.");
}

function stripTagPrefix(version) {
  return /^v\d/.test(version) ? version.slice(1) : version;
}

function versionCodeOf(version) {
  const match = semanticVersionPattern.exec(version);
  if (!match) {
    throw new Error(
      `Tunnet version ${version} must be an exact major.minor.patch version.`,
    );
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);

  if (minor > 99 || patch > 99) {
    throw new Error(
      `Tunnet version ${version} cannot be encoded as major * 10000 + minor * 100 + patch; ` +
        "minor and patch must each be at most 99.",
    );
  }

  const code = major * 10_000 + minor * 100 + patch;
  if (!Number.isSafeInteger(code) || code < 1 || code > 2_147_483_647) {
    throw new Error(
      `Tunnet version ${version} cannot be encoded as an Android versionCode.`,
    );
  }

  return code;
}

function resolveAppVersion({ injected, cargoVersion }) {
  const source = injected?.trim() || cargoVersion.trim();
  if (!source) {
    throw new Error(
      "A Tunnet version is required from TUNNET_VERSION or Cargo.toml.",
    );
  }

  const version = stripTagPrefix(source);
  return { version, versionCode: versionCodeOf(version) };
}

module.exports = {
  cargoWorkspaceVersion,
  resolveAppVersion,
  stripTagPrefix,
  versionCodeOf,
};
