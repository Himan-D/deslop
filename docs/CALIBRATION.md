# Calibration: Deslop on Open-Source Repositories

This records how Deslop's output changed after the calibration work, measured on nine open-source repositories. Numbers are reproducible from the commits listed at the end.

## Method

1. Shallow-clone each repository at its default branch (depth 1).
2. Scan each with the pre-change binary and the post-change binary, using `deslop scan <repo> --format json` with every LLM key unset.
3. Spot-check findings by hand: a random sample of up to six per finding kind, judged from the source at the reported line.

The spot-checks are a sanity pass, not a measured precision. The sample is small, and I made the judgments myself. Treat the verdicts below as directional.

## Results

| Repo | LOC | Index before | Index after | Findings before | Findings after | After, by kind |
|---|---:|---:|---:|---:|---:|---|
| BurntSushi/ripgrep | 55,477 | 53.5 | 5.9 | 655 | 118 | Cycle 39, StructuralClone 32, TollboothWrapper 30, GodObject 17 |
| colinhacks/zod | 103,326 | 6.7 | 0.4 | 395 | 10 | StructuralClone 5, Cycle 3, GodObject 2 |
| date-fns/date-fns | 110,441 | 3.7 | 1.0 | 147 | 27 | StructuralClone 25, Cycle 2 |
| dtolnay/anyhow | 5,857 | 38.3 | 5.8 | 47 | 11 | Cycle 5, StructuralClone 4, DeadOrphan 1, GodObject 1 |
| gin-gonic/gin | 24,556 | 21.2 | 1.1 | 228 | 13 | TollboothWrapper 8, Cycle 4, StructuralClone 1 |
| pallets/flask | 18,333 | 11.7 | 2.8 | 68 | 10 | GodObject 5, Cycle 2, StructuralClone 2, DeadOrphan 1 |
| psf/requests | 12,032 | 16.5 | 2.9 | 51 | 10 | GodObject 6, Cycle 3, StructuralClone 1 |
| serde-rs/serde | 42,627 | 34.7 | 1.6 | 238 | 26 | Cycle 11, StructuralClone 7, TollboothWrapper 6, GodObject 2 |
| spf13/cobra | 16,765 | 7.5 | 0.6 | 57 | 5 | TollboothWrapper 4, Cycle 1 |

Across the corpus, DeadOrphan went from 612 findings to 2. Tollbooths went from 973 to 48. Clones went from 186 to 77. Cycles were previously reported under a mislabeled kind (`BarrelBloat`): 76 before, 70 after, so the counts are not directly comparable.

**Severity after:** 2 Critical, 129 Medium, 99 Low, 0 High.

## What changed, and why

Some of the drop is detection quality, and some is deliberate policy. The table below separates them.

| Change | Kind | Evidence |
|---|---|---|
| Dead code counts a name as referenced if it appears anywhere outside its definition | Detection | Sampled ripgrep DeadOrphan: `Config::is_fixed_strings` is called as `config.is_fixed_strings(...)`, which the graph cannot resolve. |
| Test code, benches, examples, fixtures, and Go `init()` are never dead | Detection | Benchmark functions and `init` were flagged. |
| Attributed items are never dead | Detection | `#[global_allocator] static ALLOC` was flagged. |
| Trait impls are not clones | Detection | serde visitor impls repeat by contract. |
| Test code is not god objects or ghost traits | Detection | Test helper classes were flagged. |
| Cycles through shared bare names are Low, with a "verify first" note | Detection | `Config::default -> StandardBuilder::new` joined unrelated types through `new` and `default`. |
| Cycle severity follows files spanned | Policy | Same-file recursion is Medium; two files High; three or more Critical. |
| Tollbooths must have a one-statement body (`loc <= 3`) | Detection | The earlier rule counted call edges only. A 5-line method that built a struct and read a field was flagged as a forwarder, and `prune` then proposed a rewrite that would not compile. |
| Auto-inlining requires a free function whose body is one call to a free function | Safety | `prune` and `apply` now skip any other wrapper, with the reason printed. |
| Public functions are not tollbooths | Policy | zod's fluent builder methods are API surface. A large part of the tollbooth drop comes from this rule. |
| Constructors and conversions are not tollbooths | Policy | `new`, `default`, `from`, `with_*`. |
| God object severity High to Medium | Policy | Sampled god objects were large core types (`Session`, `HTTPAdapter`, `Blueprint`) that are large by design. |
| Clone severity High to Medium | Policy | Sampled clones were real but low-value. |
| Score denominator floored at 1,000 LOC | Policy | A 51-line fixture scored 100 before. |

## Spot-check verdicts (final build)

- **DeadOrphan (3 items at the time of sampling, 2 false positives):** `_assert_send_sync` is a compile-time assertion; `ALLOC` is a global allocator. `_path_is_ancestor` may be real dead code. The attribute rule fixed the `ALLOC` case; the compile-time assertion is a known gap. Recall is now low by design: only names that appear nowhere else are reported.
- **Cycle (6 sampled):** Mixed. Several are mutual recursion between methods of one type (for example `matches_all` and `matches_all_candidate`), which is recursion rather than a module cycle. Those are useful but not architectural. Ambiguous-name cycles are now Low.
- **Tollbooth (8 sampled on the final build):** Six were real forwarders, such as `c.Request.Header.Get(key)` and `is_primitive_type(ty, "str")`. Two were false positives: `engine.allNoMethod = engine.combineHandlers(...)` (an assignment) and `self.ty.is_symlink() || self.follow_link` (an expression). Severity Low. Auto-rewrite rejects both, because the body must be a single call. Detection is noisier than rewriting, and rewriting is the safer path.
- **God object (6 sampled):** Large core types. Real size, intentional design. Severity now Medium.
- **Clone (6 sampled):** Real duplication, generally low-value (for example `stats` on a sink and a result type). Severity Medium.

## Known limits

- **Recall is low for dead code.** A dead function whose name appears in a comment or string elsewhere is not reported. This is the price of precision. `apply` and `prune` rely on the same rule, so they delete less.
- **The call graph resolves by bare name.** Methods with common names (`new`, `default`, `get`) can produce false cycles. Those are downgraded, not fixed.
- **Tollbooth detection is syntactic.** The detector sees call edges and line counts, not expressions. Some one-call bodies are not pass-throughs. `prune` and `apply` are stricter, so these are reported but not auto-removed.
- **Symbol extraction coverage varies.** date-fns yields about 10 symbols per KLOC, while ripgrep yields about 60. Arrow-function exports in TypeScript are likely undercounted. Coverage was not measured per language.
- **LOC counts all lines**, including blanks and comments, because the scanner uses `lines().count()`. Scores are therefore slightly lower than a code-only count would give.

## Reproducing

```
git clone --depth 1 https://github.com/BurntSushi/ripgrep
# ...same for each repo listed above
deslop scan <repo> --format json
```

Commits scanned:

```
BurntSushi/ripgrep 91f5d22
colinhacks/zod b1f6ba0
date-fns/date-fns a9739fb
dtolnay/anyhow bb1b0f9
gin-gonic/gin 0f09c3a
pallets/flask d086db8
psf/requests 3c7baaa
serde-rs/serde 0db9b3b
spf13/cobra adbc881
```
