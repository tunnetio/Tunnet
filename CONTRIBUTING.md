# Contributing to Tunnet

Thanks for your interest in contributing to Tunnet.

Tunnet is under active development and is still pre-1.0. The project favors clean architecture, modern tooling, and correctness over preserving legacy behavior or backward compatibility.

## Development requirements

### Required

* **Rust 1.98.1**
* **Bun 1.4.0**
* **Git**
* A platform-appropriate native build toolchain

The Rust toolchain is pinned by `rust-toolchain.toml`.

### Linux

Linux development additionally requires **mold**.

Tunnet configures Cargo to use mold automatically for `x86_64-unknown-linux-gnu` builds through `.cargo/config.toml`.

### Recommended

* **cargo-nextest** for running the Rust test suite

```sh
cargo install cargo-nextest --locked
```

## Getting started

Clone the repository and install the JavaScript/TypeScript dependencies:

```sh
git clone https://github.com/tunnetio/Tunnet.git
cd Tunnet
bun install
```

If you use `rustup`, entering the repository will automatically select the Rust version defined in `rust-toolchain.toml`.

Install the repository Git hooks:

```sh
bunx lefthook install
```

## Building

Build the Rust workspace with:

```sh
cargo build --workspace --exclude tunnet-desktop
```

The repository also contains multiple applications and packages managed through the Bun workspace. See the root `package.json` for the available development and build commands.

## Testing

Rust tests should preferably be run with:

```sh
cargo nextest run --workspace
```

JavaScript and TypeScript tests can be run with:

```sh
bun test
```

or through the component-specific scripts defined in the workspace.

## Formatting and linting

Before submitting a change, make sure the relevant checks pass.

For Rust:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
```

For JavaScript and TypeScript:

```sh
bun run check
```

Lefthook runs repository checks automatically at the configured Git hook stages.

## Contribution guidelines

Keep changes focused and maintainable.

Tunnet is currently pre-1.0, so contributors should not preserve outdated APIs, compatibility layers, deprecated code, or legacy architecture unless there is a concrete reason to do so.

Breaking changes are acceptable when they result in a better design.

When changing existing systems:

* prefer fixing the underlying abstraction instead of adding workarounds;
* remove obsolete code when replacing it;
* avoid compatibility shims unless they serve a current requirement;
* add or update tests for changed behavior;
* keep dependencies and implementation choices reasonably current;
* follow existing project conventions and component boundaries.

Additional engineering guidance for automated coding agents is documented in `AGENTS.md`.

## Pull requests

Before opening a pull request:

1. Make sure the project builds for the affected components.
2. Run the relevant tests.
3. Run formatting and linting checks.
4. Remove temporary debugging code and unrelated changes.
5. Document user-visible or architectural changes when appropriate.

Pull requests should explain what changed and why.

Large architectural changes should include enough context for reviewers to understand the intended design, rather than only describing the resulting diff.

## Third-party and generated material

Do not submit material that you do not have the right to contribute.

Clearly disclose copied or adapted third-party code, documentation, media, or data, including its source and license when relevant.

Substantial AI-generated or tool-generated contributions should be reviewed by the contributor as if they had written the code themselves. The contributor remains responsible for correctness, licensing, security, and provenance.

Do not commit credentials, confidential information, private keys, malicious code, or proprietary material that you are not authorized to publish.

## Contributor agreement

Contributions may require acceptance of Tunnet's applicable contributor agreement before they can be merged.

If a contribution is owned or controlled by an employer or another organization, authorization from that organization may also be required.

The contributor agreement process is separate from the public license applied to the repository.

## Licensing

Tunnet uses a component-level licensing model.

Different parts of the repository may be distributed under different licenses, and third-party material remains governed by its respective license.

The repository's licensing documentation and file-level SPDX metadata are authoritative for determining the license that applies to a particular file or component.

Commercial licensing options may also be available for applicable Tunnet components.

See:

* `LICENSE`
* the license texts under `licenses/`
* `COMMERCIAL-LICENSE.md`
* `TRADEMARKS.md`

## Review and acceptance

Submitting a contribution does not guarantee that it will be merged.

Changes may be rejected for technical, architectural, security, licensing, maintenance, or product reasons.
