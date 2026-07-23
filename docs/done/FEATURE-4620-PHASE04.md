# FEATURE-4620 — PHASE04 — Release runbook & final cut prep

**Status:** DONE
**Branch:** `feature/feature-4620-phase04-release-runbook` (cut from the PHASE03 commit `c0949ff`)

## Summary

Final phase of the v1.0.0 release preparation. Added the committed release checklist
`docs/RELEASE.md` (from the house `dotnet-release` template, placeholders filled for this repo),
then ran the release-config pre-flight end-to-end: a zero-warning Release build across all three
TFMs, the full test suite green, and a `dotnet pack` verified to produce `Enigma.Core.1.0.0.nupkg`
embedding `README.md` + `LICENSE.md` with correct metadata. The pack/tag/push publish runbook is
**printed to the console for the maintainer, never executed**; no NuGet API key is stored or echoed.
With this phase the base FEATURE-4620 item is complete.

## Files/modules touched

**Created**

- `docs/RELEASE.md` — the human release runbook (pre-flight → merge → tag → pack → push → verify),
  instantiated from the house template with this repo's specifics: `PackageId=Enigma.Core`,
  solution `Enigma.Core.slnx`, lib csproj `src/Enigma.Core/Enigma.Core.csproj`, lib dir
  `src/Enigma.Core/`, default branch `main`, bare `X.Y.Z` tag (repo has no tags yet).
- `docs/done/FEATURE-4620-PHASE04.md` (this file).

**Modified**

- `docs/roadmap.md` — PHASE04 status `TODO → IN PROGRESS → DONE`; the base FEATURE-4620 row flipped
  `IN PROGRESS → DONE` (final phase completed).
- `docs/plan/FEATURE-4620.md` — PHASE04 status `IN PROGRESS → DONE`; the plan's top-level
  `**Status:**` flipped to `DONE (multi-phase)`.

**Deleted:** none. (`./artifacts/` holds the packed `.nupkg` from verification; it is gitignored and
not committed.)

## Acceptance criteria — verification

1. ✅ `docs/RELEASE.md` complete and accurate for this repo — every placeholder filled with the real
   package id, solution, csproj/dir, default branch, and tag convention; no `{{…}}` tokens remain.
2. ✅ Release build + test green (see evidence); pack verified to embed `README.md` + `LICENSE.md`.
3. ✅ Runbook printed to the console (never executed); no API key stored or echoed — the push command
   shows `<NUGET_API_KEY>` as a placeholder only.

## Build/test evidence

- **Build:** `dotnet build Enigma.Core.slnx -c Release` → **Build succeeded. 0 Warning(s),
  0 Error(s)** across `netstandard2.0`, `net8.0`, `net10.0` (with `TreatWarningsAsErrors=true`).
- **Tests:** `dotnet test --solution Enigma.Core.slnx -c Release` → **Passed!** total **3254**,
  failed 0, skipped 0 (net8.0 + net10.0 test assemblies).
- **Pack:** `dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts` →
  `Successfully created package 'Enigma.Core.1.0.0.nupkg'`. Inspected the nupkg + nuspec:
  - Embedded `README.md` (3789 B) and `LICENSE.md` (1062 B) at the package root.
  - `lib/{netstandard2.0,net8.0,net10.0}/Enigma.Core.dll` + XML docs present for all three TFMs.
  - `<id>Enigma.Core`, `<version>1.0.0`, `<title>`, `<license type="file">LICENSE.md`,
    `<readme>README.md`, `<projectUrl>`/`<repository>`, `<releaseNotes>`, `<copyright>`, and `<tags>`
    all present and correct.
  - Dependencies: `BouncyCastle.Cryptography` 2.6.2 on all three TFMs; `System.Buffers` 4.6.1 on
    `.NETStandard2.0` only. `PolySharp` correctly **not** listed (compile-only, `PrivateAssets=all`).
  - No `.snupkg` emitted — symbol packages are not configured this release (as intended).

## Deviations & follow-ups

- **Template tailoring (`docs/RELEASE.md`).** The house template's step 5 states that `dotnet pack`
  also emits a `.snupkg` and that pushing the `.nupkg` uploads symbols automatically. This release
  deliberately excludes SourceLink / symbol packages (see the plan's *Out of scope*), and pack was
  verified to emit only the `.nupkg`. That sentence was reworded to state no symbol package is
  produced, so the runbook is accurate for this repo. No other deviations from the plan.
- **Runbook is print-only.** Per the plan and the `dotnet-release`/dev-workflow boundary, the
  outward-facing `git tag` / `dotnet nuget push` and the merge-to-`main` steps are printed for the
  maintainer to run; only the local, reversible `build`/`test`/`pack` verification commands were
  executed here.
- **Item complete.** FEATURE-4620 (all four phases) is now `DONE`; the 1.0.0 cut is ready per
  `docs/RELEASE.md`.
- **Line endings (CRLF):** no line-ending churn observed — `git status` showed only clean content
  diffs on the touched/new files, no whole-file CRLF↔LF rewrite. `.gitattributes` is present.
  Recommendation-only per the workflow; no action taken.
