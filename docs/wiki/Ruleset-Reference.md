# Ruleset Reference (`deslop.toml`)

Place a `deslop.toml` file in the root of your repository to enforce ArchUnit-style architectural boundaries. Deslop automatically loads `deslop.toml` during `deslop scan`, `deslop check`, and all `deslop mcp` tool calls.

Violations are emitted as `LayerViolation` findings with `Critical` severity and `1.0` confidence.

---

## Schema Overview

`ArchitectureConfig` (`crates/deslop-core/src/lib.rs`) expects the following top-level fields:

```toml
# Required: ordered list of layers from highest (top) to lowest (bottom).
# Use `layers = []` if you only want `[[forbidden_rules]]`.
layers = [
    "apps/*/**",
    "src/domain/**",
]

# Required: explicit forbidden boundary rules (use `forbidden_rules = []` if none).
[[forbidden_rules]]
from = "src/domain/**"
to = "apps/*/**"
description = "Domain layer cannot import from application entrypoints."

# Optional: suppress specific intentional cross-boundary edges.
[[allow_exceptions]]
from = "src/domain/legacy_bridge.ts"
to = "apps/web/**"
reason = "Temporary bridge while extracting port interface."
```

> **Note:** Both `layers` and `forbidden_rules` must be present in `deslop.toml` (empty arrays `[]` are valid). `allow_exceptions` is optional and defaults to empty.

---

## 1. `layers` (Strict Monotonic Ordering)

`layers` defines a top-to-bottom hierarchy:

- Index `0` is the **highest** layer (e.g. controllers, CLI, apps).
- Higher indices are **lower** layers (e.g. services, domain, core, repositories).
- A module in `layers[i]` **may depend on** `layers[j]` only when `i <= j` (same layer or lower).
- If a module in `layers[i]` depends on `layers[j]` where `i > j`, Deslop emits a `LayerViolation` (`Critical`):
  ```text
  Layer Inversion: Layer 'src/domain/**' imports upper Layer 'apps/*/**'
  ```

Modules that do not match any pattern in `layers` are not checked against monotonic ordering (though they are still checked against `forbidden_rules`).

---

## 2. `forbidden_rules` (Explicit Boundary Bans)

Each `[[forbidden_rules]]` table bans any dependency edge from `from` to `to`, regardless of whether either path appears in `layers`:

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `from` | `string` | Yes | Pattern matching the source symbol's file path. |
| `to` | `string` | Yes | Pattern matching the target symbol's file path. |
| `description` | `string` | No | Custom human-readable explanation printed in findings and SARIF output. |

---

## 3. Pattern Matching & Globs (`matches_pattern`)

Deslop normalizes path separators (`\` -> `/`) and evaluates patterns with two modes:

1. **Glob mode (when the pattern contains `*`)**:
   - `*` matches any characters within a **single path segment**.
   - `**` matches **zero or more path segments**.
   - Examples:
     - `src/domain/**` — matches any file under `src/domain/`.
     - `apps/*/**` — matches any file inside any immediate subdirectory of `apps/`.
     - `crates/deslop-core/**` — matches all Rust files inside the `deslop-core` crate.
2. **Substring mode (when the pattern contains no `*`)**:
   - Matches if the normalized file path contains the pattern string.
   - Backward-compatible with simple layer names like `layers = ["controller", "service", "repo"]`.

---

## 4. `allow_exceptions` (Scoped Suppressions)

Use `[[allow_exceptions]]` to carve out documented exceptions without weakening a layer or forbidden rule for the rest of the codebase:

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `from` | `string` | Yes | Pattern matching the source file path. |
| `to` | `string` | Yes | Pattern matching the target file path. |
| `reason` | `string` | No | Documents why the exception is permitted (defaults to `""`). |

For each dependency edge, Deslop checks `allow_exceptions` **before** evaluating `forbidden_rules` and `layers`. If **any** exception matches both `from` and `to`, that edge is skipped; all other edges in the same module continue to be enforced.

---

## 5. Slop Index Scoring & Gate Thresholds

### Slop Index Formula

The Slop Index (`0.0` to `100.0`) is a weighted finding density per 1,000 lines of code:

| Severity | Weight | Typical Findings |
| :--- | :--- | :--- |
| `Low` | `1.5` | `BareHeuristic` cycles, minor wrappers |
| `Medium` | `4.0` | Same-file cycles, structural clones, dead orphans |
| `High` | `8.0` | Two-file dependency cycles, god objects |
| `Critical` | `15.0` | 3+ file dependency cycles, `LayerViolation` (`deslop.toml`) |

$$\text{Slop Index} = \text{clamp}\left(\frac{\sum \text{weight}}{\max(\text{LOC}, 1000) / 1000},\ 0.0,\ 100.0\right)$$

- **Minimum LOC floor (`1,000`)**: Small projects are floored at 1,000 LOC so a handful of findings cannot saturate the score (`score_reliable: false` in JSON output below 1,000 LOC).

### `deslop check` Exit-Code Gate

`deslop check` is designed for CI and pre-commit/agent gates:

- Fails (non-zero exit) on any **new** `Cycle`, `LayerViolation`, or `High`/`Critical` finding (when `--base <ref>` is set, only findings introduced relative to `<ref>` fail the gate).
- Fails if `--max-slop <N>` is passed and the computed Slop Index exceeds `N`.
