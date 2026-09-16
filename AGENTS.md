## Engineering Philosophy

* **Break freely before 1.0.** Prefer the best architecture over backward compatibility.
* **No legacy by default.** Remove obsolete code, APIs, compatibility layers, and abstractions instead of preserving them.
* **Git is the archive.** Deleted code and historical context do not need to remain in the codebase.
* **Design for the future, not the past.** Ask how the system should be built today, not how to preserve yesterday's design.
* **Prefer modern technology.** Favor new, innovative, state-of-the-art approaches when they provide meaningful advantages.
* **Stay current.** Keep dependencies, tooling, language features, runtimes, and standards as up-to-date as practical.
* **Accept calculated risk.** Prefer experimentation and technological progress over stagnation.
* **Rewrite when justified.** Do not stack workarounds on top of fundamentally wrong abstractions.
* **Delete aggressively.** Dead code, deprecated paths, temporary shims, stale comments, and unnecessary complexity should disappear.
* **Move fast without sacrificing rigor.** Breaking changes are acceptable; regressions, poor testing, and unjustified complexity are not.
* **Optimize pre-1.0 software for evolution, not preservation.**

## Rust Idioms

* **Use Rust’s type system instead of manual encodings.** Prefer enums, newtypes, and typed variants over `u8`/`bool` tags, magic constants, or structs that manually emulate enums. Make invalid states unrepresentable whenever practical.

## Writing and Documentation

* **Be direct, concrete, and concise.** Avoid filler, repetition, inflated language, generic framing, and formulaic AI-style prose.
* **Relevance is part of correctness.** Include only information that serves the purpose and audience of the text.
* **Do not over-explain.** Prefer dense, useful information over exhaustive coverage.
* **Write for the current system.** Do not preserve historical narratives, migration diaries, or descriptions of obsolete behavior.
* **Keep concerns scoped.** User-facing documentation should focus on user-relevant behavior; implementation details belong only where they are useful to developers or operators.

## Comments

* **Comments must add information the code cannot express clearly.** Use them for non-obvious invariants, safety requirements, protocol constraints, external quirks, or important reasoning.
* **Do not narrate history or obvious behavior.** Comments should describe the current truth, not previous implementations or the sequence of changes.
* **Prefer better code over explanatory comments.** Use clearer names, types, functions, and structure whenever possible.

## Tooling

* **Rust tests:** Prefer `cargo nextest` over `cargo test`.
