# FEATURE-28C7 — Release-doc polish: drop Downloads badge & verify guide/README samples

**Status:** DONE
**Type:** FEATURE (single-phase)
**Branch:** `feature/feature-28c7-doc-polish` (cut from `develop` @ `d946d87`)

## Summary

Final documentation polish ahead of the v1.0.0 NuGet cut:

1. Removed the NuGet **Downloads** badge (`![Downloads](…/nuget/dt/…)`) from the root `README.md`,
   keeping the NuGet-version and License badges. This aligns the README with the house
   `dotnet-release` badge convention (NuGet-version + License standard; Downloads optional).
2. Ran the last correctness pass over every C# sample in the docs against the public API. **No
   sample changes were required** — every snippet already matches the current public surface.

## Files/modules touched

**Modified**
- `README.md` — deleted the single Downloads-badge line (1 line removed; the Quick-start code block
  and all prose untouched).
- `docs/roadmap.md` — `FEATURE-28C7` status `TODO` → `IN PROGRESS` → `DONE`.
- `docs/plan/FEATURE-28C7.md` — status `TODO` → `IN PROGRESS` → `DONE`.

**Created**
- `docs/done/FEATURE-28C7.md` — this completion record.

**Not modified**
- No file under `docs/guides/` — the verification pass found zero discrepancies.
- No `src/` or `tests/` file; no dependency, version, or config change.

## Verification pass — how the samples were checked

Acceptance criterion 2 (every snippet verified against `src/`) was met by a comprehensive,
symbol-by-symbol audit cross-checking each API reference in the code fences against the public types
in `src/Enigma.Core/` — `using Enigma.Core.*` namespaces, factory types + `Create*Service` methods,
service members and their argument shapes (including sync/async + `await`), static helpers
(`RandomUtils.*`, `CryptoDefaults.*`), extension methods, and enums.

**Coverage: 60 snippets · 209 distinct API symbols · 0 mismatches · 0 uncertain**, across all 13
category guides plus the root `README.md` Quick-start snippet:

| Target | Snippets | Symbols | Mismatch | Uncertain |
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

**Validity for this build:** the audit was run during planning against the same tree this branch was
cut from. The only commit since (`d946d87`) touched only `docs/plan/` + `docs/roadmap.md`, and this
build's sole content edit is the README badge line — so `src/`, `docs/guides/`, and the README
Quick-start block are byte-identical to the audited baseline. No re-verification was needed; there
was no drift to fix.

## Build/test evidence

Docs-only change — **there was nothing to compile or unit-test.** DoD criteria 1–2 are satisfied by
inspection:
- The badge removal was confirmed by re-reading `README.md` (no remaining `nuget/dt` reference; the
  NuGet-version and License badges remain and are well-formed).
- The sample verification is evidenced by the audit table above.

No `src/`/`tests/` code changed, so the solution build and MTP test suite are unaffected.

## Deviations & follow-ups

- **No deviation from the plan.** The plan anticipated that the badge removal would be the only
  guaranteed edit and that the guides would likely need no changes; that is exactly what occurred.
- **Line endings:** `README.md` is LF-only — no CRLF noise observed in any touched file, so no
  normalization recommendation applies.
- **Follow-up (optional, out of scope):** there is still no automated doc-sample compile harness, so
  future public-API changes could silently drift the guide snippets. A permanent doc-sample test was
  considered during planning and deliberately declined for this release. Worth reconsidering
  post-1.0.0 if the API surface starts changing frequently.
