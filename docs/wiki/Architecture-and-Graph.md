# Architecture & Symbol Dependency Graph

This page documents Deslop's internal workspace boundaries, how source files are parsed across languages, and how the Symbol Dependency Graph (SDG) detects cycles and grades edge confidence.

---

## 1. Workspace Crate Boundaries

Deslop is structured as a 7-crate Cargo workspace (`Cargo.toml`) with strict acyclic crate boundaries enforced both by Cargo and by the repository's own [`deslop.toml`](../../deslop.toml):

| Crate | Responsibility | Internal Dependencies |
| :--- | :--- | :--- |
| `deslop-core` | Domain models (`Symbol`, `DependencyEdge`, `SlopFinding`, `ArchitectureConfig`), spans, and metric primitives | None |
| `deslop-parser` | Multi-threaded AST extraction (`syn` for Rust, Tree-sitter `UniversalParser` for TS/JS/Py/Go) and `.deslop/cache.json` incremental hashing | `deslop-core` |
| `deslop-graph` | `petgraph` Symbol Dependency Graph, Tarjan SCC cycle detection, FAS cut-edge heuristic, package coupling ($C_a, C_e, I, A, D$), and dominator analysis | `deslop-core` |
| `deslop-detector` | Deterministic anti-pattern rules (`ArchitectureViolationRule`, `CircularDependencyRule`, `DeadOrphanRule`, `TollboothWrapperRule`, `GhostAbstractionRule`, `StructuralCloneRule`, `GodObjectRule`) and Slop Index scoring | `deslop-core`, `deslop-graph` |
| `deslop-llm` | Zero-dependency BYOK client (Gemini, OpenAI, Anthropic, OpenRouter, Offline) used only when `--explain` or `--llm` is explicitly passed | `deslop-core` |
| `deslop-inversion` | `DelooperEngine`, `InversionEngine`, pruning/inlining diff synthesis, and atomic snapshot rollback | `deslop-core`, `deslop-graph`, `deslop-detector`, `deslop-llm` |
| `deslop-cli` | Unified `deslop` binary (`scan`, `check`, `deloop`, `invert`, `prune`, `apply`, `deep`, `profile`, `churn`, `mcp`, `lsp`, `tui`, `scip`, `testgen`, `trace`, `capacity`) | All 6 library crates |

---

## 2. Polyglot AST Parsing & `tsconfig.json` Resolution

`deslop-parser` exposes a `FileParser` trait implemented by:

- **`RustParser`** (`syn`): Full AST extraction of Rust modules, structs, traits, impls, functions, visibility, spans, and call expressions.
- **`UniversalParser`** (Tree-sitter): Polyglot extraction for **TypeScript**, **JavaScript**, **Python**, and **Go** (functions, classes, interfaces, imports, and calls).
- **`CodebaseScanner` + `CodebaseCache`**: Walks the workspace in parallel with `rayon` and caches SHA-256 content digests, `mtime`, extracted symbols, edges, and LOC in `.deslop/cache.json` so unchanged files skip re-parsing.

### `tsconfig.json` Path Alias Expansion

For TypeScript/JavaScript monorepos and path-aliased projects, `deslop-graph` searches the common ancestor directory of parsed files for `tsconfig.json` (`load_tsconfig_aliases`) and extracts `compilerOptions.paths` mappings (for example, `@/* -> src/*` or `@auth -> src/lib/auth`). During graph construction, `expand_tsconfig_import` rewrites aliased import paths before resolving callees, turning otherwise opaque alias imports into `ImportScoped` edges.

---

## 3. Symbol Dependency Graph (SDG)

`SymbolGraph` (`crates/deslop-graph/src/lib.rs`) wraps a `petgraph::graph::DiGraph<Symbol, DependencyEdgeKind>`:

- **Dual Indexing ($O(1)$ amortized lookup)**:
  - Primary map: `HashMap<String, NodeIndex>` keyed by fully-qualified symbol ID.
  - Secondary map: `HashMap<&str, NodeIndex>` keyed by unqualified base symbol name.
- **Edge Resolution**: Runs in $O(|E|)$ total time across all extracted dependency edges.

### Edge Resolution Provenance (`EdgeResolution`)

Every edge `(from, to)` in `SymbolGraph` records how it was resolved:

| `EdgeResolution` | How It Was Resolved | Confidence Impact |
| :--- | :--- | :--- |
| `Exact` | Direct symbol ID hit, `Self::` same-file hit, or qualified `match_qualified` hit | Highest confidence |
| `ImportScoped` | Resolved via `normalize_callee` import alias, `file_imports`, or expanded `tsconfig.json` path alias | High confidence (scoped by explicit file imports) |
| `BareHeuristic` | Resolved via unqualified bare-name global lookup (`cands.len() == 1`) or same-file unqualified fallback | Lower confidence; cycles containing a `BareHeuristic` edge are downgraded to `Low` severity with a verification note |

---

## 4. Tarjan SCC Cycle Detection & FAS De-Looping

1. **Tarjan's Strongly Connected Components (SCC)**:
   - Runs in $O(|V| + |E|)$ time and $O(|V|)$ auxiliary stack space.
   - Identifies every strongly connected component with $|V_{\text{scc}}| > 1$ (or self-loops).
2. **Cycle Grading**:
   - **Within 1 file**: `Medium`
   - **Across 2 files**: `High`
   - **Across 3+ files**: `Critical`
   - **Contains `BareHeuristic` edge**: Downgraded to `Low` with a `"verify first"` note so ambiguous bare names (such as `new` or `default`) do not cause noisy false-positive build breaks.
3. **Feedback Arc Set (FAS) Cut-Edge Selection**:
   - For a cycle $C = (v_1 \to v_2 \to \dots \to v_k \to v_1)$, `deslop deloop` scores each edge by call volume and target size/complexity:
     $$W(u, v) = \text{CallVolume}(u, v) \times (\text{LOC}(v) + \text{Complexity}(v))$$
   - The minimum-weight edge $\min_{e \in C} W(e)$ is surfaced as the optimal cut candidate, paired with leaf-module extraction or dependency-inversion steps.
