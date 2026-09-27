# Deslop Architecture & Systems Blueprint

## 1. System Philosophy

Deslop is built on two foundational software engineering disciplines:
1. **The Unix / Linux Philosophy**: Modularity, clarity, composition, parsimony, silence on success, and robust repair on failure.
2. **Deep Module Design**: Modules with narrow interfaces that encapsulate substantial operational depth, penalizing shallow pass-through layers ("tollbooth wrappers") and speculative 1:1 interfaces ("ghost abstractions").

---

## 2. Workspace Topology & Crate Boundaries

```
deslop/
├── crates/deslop-core       # Domain models, symbols, spans, and metric primitives
├── crates/deslop-parser     # Multi-threaded AST extraction (syn + Rayon + polyglot lexer)
├── crates/deslop-graph      # Directed graph, cycle detection, profiler & deep analyzer
├── crates/deslop-detector   # Deterministic anti-pattern and slop detection algorithms
├── crates/deslop-inversion  # FAS cycle breaking, refactoring engine & snapshot rollback
├── crates/deslop-llm        # Zero-dep BYOK client (Gemini/OpenAI/Anthropic/OpenRouter/Offline)
└── crates/deslop-cli        # Unified command-line interface
```

### Dependency Invariants
- `deslop-core` has zero internal crate dependencies.
- `deslop-parser` and `deslop-detector` depend only on `deslop-core` (and `deslop-graph` for graph-level queries).
- `deslop-inversion` coordinates refactoring actions across `deslop-graph` and `deslop-core`.
- `deslop-cli` serves as the compositional orchestration harness. Circular crate references are prevented by Cargo workspace boundaries.

---

## 3. Algorithmic Bounds & Graph Representation

### 3.1 Directed Symbol Graph (DiGraph)
- **Data Structure**: `petgraph::graph::DiGraph<Symbol, DependencyEdgeKind>`
- **Index Lookups**: $O(1)$ amortized. Nodes are dual-indexed:
  - Primary: `HashMap<String, NodeIndex>` indexed by fully-qualified symbol ID.
  - Secondary: `HashMap<&str, NodeIndex>` indexed by unqualified base symbol name.
- **Edge Resolution Complexity**: $O(|E|)$ total, replacing naive $O(|V| \cdot |E|)$ linear searches.

### 3.2 Cycle Detection & De-Looping
- **Algorithm**: Tarjan's Strongly Connected Components (SCC).
- **Time Complexity**: $O(|V| + |E|)$.
- **Space Complexity**: $O(|V|)$ auxiliary stack space.
- **Feedback Arc Set (FAS) Heuristic**:
  For an SCC with cycle $C = (v_1 \to v_2 \to \dots \to v_k \to v_1)$, the engine evaluates the edge weight:
  $$W(u, v) = \text{CallVolume}(u, v) \times (\text{LOC}(v) + \text{Complexity}(v))$$
  The minimum weight edge $\min_{e \in C} W(e)$ is selected as the optimal cut candidate.

### 3.3 Dominator & Chokepoint Discovery
- **Reachability Model**: Forward Breadth-First Search (BFS) from candidate root nodes.
- **Downstream Domination**:
  $$\text{ReachRatio}(u) = \frac{|\text{ReachableNodes}(u)|}{|V|}$$
  Nodes with $\text{ReachRatio} > 0.35$ and incoming degree $\ge 3$ are flagged as single points of architectural failure.

---

## 4. Architectural Physics: The Main Sequence

Deslop implements Robert C. Martin's Package Coupling & Cohesion metrics:

1. **Afferent Coupling ($C_a$)**: The number of symbols outside this module that depend on symbols inside this module. Measures incoming responsibility.
2. **Efferent Coupling ($C_e$)**: The number of symbols inside this module that depend on symbols outside this module. Measures outgoing dependence.
3. **Instability ($I$)**:
   $$I = \frac{C_e}{C_a + C_e}$$
   - $I = 0.0$: Maximally stable. Depended upon heavily, changes have high blast radius.
   - $I = 1.0$: Maximally unstable. Dependent on external components, easy to change.
4. **Abstractness ($A$)**:
   $$A = \frac{\text{Abstract Symbols (traits, interfaces)}}{\text{Total Symbols}}$$
5. **Normalized Distance from the Main Sequence ($D$)**:
   $$D = |A + I - 1.0|$$

### Classification Zones
- **Main Sequence ($D \le 0.25$)**: Optimal balance between stability and abstractness.
- **Zone of Pain ($A \to 0, I \to 0$)**: Highly concrete and heavily depended on. Extremely rigid and painful to refactor.
- **Zone of Uselessness ($A \to 1, I \to 1$)**: Highly abstract with no dependents. Pure speculative indirection.

---

## 5. Ousterhout's Deep Module Metric

Deslop evaluates the depth ratio of individual components:

$$\text{Interface Complexity} = 2 \times \text{ParamCount} + \left\lfloor \frac{\text{SignatureLength}}{25} \right\rfloor$$
$$\text{Implementation Power} = \text{LOC} + 4 \times \text{CyclomaticComplexity}$$
$$\text{Depth Ratio} = \frac{\text{Implementation Power}}{\max(1, \text{Interface Complexity})}$$

- **Deep Module ($\text{Ratio} \ge 3.0$)**: Narrow surface area, substantial internal functionality.
- **Shallow / Slop Module ($\text{Ratio} < 1.5$)**: Wide interface with trivial implementation. Candidates for inline pruning.

---

## 6. Verification and Atomic Rollback

Refactoring operations follow an atomic journal protocol:
1. Read target files into memory: `HashMap<PathBuf, String>`.
2. Apply surgical inlining and dead-code pruning mutations.
3. Flush modified buffers to disk.
4. Execute user-supplied verification command (e.g. `cargo test`, `make test`).
5. Inspect return exit code:
   - `0`: Mutation committed.
   - Non-zero: Restore original buffers from memory snapshot (< 5ms), abort mutation, and emit verification errors to `stderr`.

---

## 7. Performance Budget & Compilation Flags

The release profile (`Cargo.toml`) enforces:
- `opt-level = 3`: Maximum compiler optimizations.
- `lto = "fat"`: Cross-crate Link-Time Optimization.
- `codegen-units = 1`: Single code generation unit for maximal inline optimization.
- `panic = "abort"`: Zero unwinding tables, compact binary size (~5.5MB stripped).
