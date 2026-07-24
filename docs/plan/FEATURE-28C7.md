# FEATURE-28C7 — Release-doc polish: drop Downloads badge & verify guide/README samples

**Status:** DONE
**Type:** FEATURE (single-phase)
**Branch (at build time):** `feature/feature-28c7-doc-polish` — cut from current `HEAD` when `/build` runs.

## Objective

Final documentation polish ahead of the v1.0.0 NuGet cut (follows the now-`DONE`
[FEATURE-4620](FEATURE-4620.md)):

1. Remove the NuGet **Downloads** badge from the root `README.md`.
2. Do a last correctness pass over every code sample in the docs, verifying it against the real
   public API and **fixing any mismatch in place**.

Documentation only — no `src/` or test changes.

## Context & constraints

- **Evolution of an existing codebase.** Enigma.Core (service + factory + DI, BouncyCastle-backed).
- The guides under `docs/guides/` and the summary `README.md` were authored in **FEATURE-4620**
  (PHASE02 / PHASE03) and are otherwise correct.
- **No sample-compile harness exists** in the repo (the only `tests/…/Api/` test is
  `BouncyCastleIsolationTests`). The check is therefore a **manual review against the public
  surface in `src/`**, not the running of an existing tool. (A permanent doc-sample test harness was
  considered during planning and deliberately declined — out of scope for a pre-release check.)
- **Badge convention** (`dotnet-release` skill): NuGet-version + License are the standard pair; the
  Downloads badge is the *optional* one — removing it is the sanctioned deviation, no conflict.
- **Docs-only Definition of Done.** There is nothing to compile or unit-test; DoD criteria 1–2 are
  met by inspection against `src/` (well-formed Markdown, samples confirmed against the public API).
  Criteria 3–5 (acceptance criteria, roadmap/plan status, completion doc) still apply.
- CRLF/line-ending noise, if spotted in a touched file, is recorded as a one-line recommendation in
  the completion doc only — never fixed here (per `dev-workflow`).

## Scope

**In scope**
- `README.md` — delete the `[![Downloads](…nuget/dt/…)]` badge (currently line 4). Keep the
  NuGet-version badge (line 3) and the License badge (line 5).
- Verify the C# samples in all **13 category guides** under `docs/guides/`:
  `block-ciphers, certificates, encoding, extensions, hashing, hmac, key-derivation, otp, padding,
  pqc, public-key, stream-ciphers, utils`.
- Verify the **Quick-start** snippet in the root `README.md` (it ships inside the NuGet package).

**Out of scope**
- `docs/guides/README.md` (index — no code, read-through only).
- Any `src/` or `tests/` change; any new test/harness; any dependency or version bump.
- The NuGet-version and License badges (retained).

## Design / approach

1. **Badge removal.** Remove the single Downloads-badge line from `README.md`; confirm the remaining
   two badges still render.
2. **Sample verification.** For each in-scope file, cross-check every API reference in its code
   fences — `using Enigma.Core.*` namespaces, factory types + `Create*Service` methods, service
   members and their argument shapes (incl. sync/async + `await`), static helpers
   (`RandomUtils.*`, `CryptoDefaults.*`), extension methods, enums/options — against the public
   types in `src/Enigma.Core/`. Correct any mismatch (wrong name/namespace/signature) in place.
3. **Report.** Record in the completion doc every discrepancy found and its fix, or state explicitly
   that none were found.

### Planning-time audit baseline (preliminary evidence — re-confirm at build time)

A 14-reader parallel audit run **during planning** cross-checked every snippet against `src/`.
It found **0 mismatches / 0 uncertain** across **60 snippets / 209 distinct API symbols**:

| Target | Snippets | Symbols checked | Mismatch | Uncertain |
|--------|:---:|:---:|:---:|:---:|
| block-ciphers.md | 5 | 26 | 0 | 0 |
| certificates.md | 11 | 25 | 0 | 0 |
| encoding.md | 3 | 10 | 0 | 0 |
| extensions.md | 3 | 15 | 0 | 0 |
| hashing.md | 3 | 8 | 0 | 0 |
| hmac.md | 3 | 12 | 0 | 0 |
| key-derivation.md | 2 | 16 | 0 | 0 |
| otp.md | 6 | 28 | 0 | 0 |
| padding.md | 2 | 12 | 0 | 0 |
| pqc.md | 5 | 17 | 0 | 0 |
| public-key.md | 6 | 16 | 0 | 0 |
| stream-ciphers.md | 3 | 12 | 0 | 0 |
| utils.md | 4 | 6 | 0 | 0 |
| README.md (Quick-start) | 1 | 6 | 0 | 0 |
| **Total** | **60** | **209** | **0** | **0** |

This is a planning aid, not a substitute for the build-time pass: `/build` re-verifies and fixes any
drift. The expected outcome, given this baseline, is that the **only guaranteed edit is the badge
removal** and the guides need no changes — but the verification pass is still performed and its
result recorded.

## Acceptance criteria

1. `README.md` no longer contains the `nuget/dt` Downloads badge; the NuGet-version and License
   badges remain and render correctly.
2. Every code snippet in the 13 guides and the README Quick-start has been verified against
   `src/Enigma.Core/`; every mismatch (if any) is corrected in place.
3. The completion doc `docs/done/FEATURE-28C7.md` lists each discrepancy found (`file:line` → fix),
   or states explicitly that none were found, and notes that the change is docs-only (nothing to
   build or unit-test).
4. Roadmap row and this plan file are set to `DONE` on completion.
