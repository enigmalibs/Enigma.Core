# FEATURE-4620 — PHASE03 — Summary README + release notes + community files

**Status:** DONE
**Branch:** `feature/feature-4620-phase03-readme-notes-community` (cut from the PHASE02 commit `04d9629`)

## Summary

Produced the user-facing release documentation and community files for the v1.0.0 NuGet release:
the summary-style root `README.md` (replacing the PHASE01 placeholder), the initial
`RELEASENOTES.md` (was an empty file), a finalized `<PackageReleaseNotes>` in the library csproj,
`SECURITY.md`, and `CLAUDE.md`. The README is summary-only with a **prose-only** Documentation
pointer to the `docs/guides/` set produced in PHASE02 — no clickable per-guide links, no absolute
GitHub URLs. Because this phase edits the csproj, the full Release build was kept green across all
three TFMs, the test suite re-run, and the pack re-verified to embed the now-non-empty README.

## Files/modules touched

**Created**

- `SECURITY.md` — supported versions + responsible disclosure via GitHub private vulnerability
  reporting (Security tab → Report a vulnerability); no email exposed; notes the crypto-library
  sensitivity and points BouncyCastle-rooted issues upstream.
- `CLAUDE.md` — repo guide for AI agents: architecture (service + factory + DI; BouncyCastle-backed;
  the `BouncyCastleIsolationTests` public-surface invariant), project layout, target frameworks &
  dependencies, build/test/pack commands (MTP + xunit.v3), conventions, and the dev-workflow tracking
  model. Describes Enigma.Core specifically (written from the actual repo — no prior CLAUDE.md
  existed in-repo to adapt).
- `docs/done/FEATURE-4620-PHASE03.md` (this file).

**Modified**

- `README.md` — replaced the PHASE01 placeholder with the summary README: title, three badges
  (NuGet version, Downloads, License → `LICENSE.md`), one-paragraph intro (brand-new library on
  BouncyCastle; no Enigma.Cryptography mention), a `> **What's new in 1.0**` callout →
  `RELEASENOTES.md`, a Features list grouped by category, an async/progress/cancellation note,
  Installation (`dotnet add package Enigma.Core`) + supported-TFMs line, a short verified Quick-start
  snippet, and a **prose-only** Documentation section pointing to `docs/guides/`.
- `RELEASENOTES.md` — filled the empty file with `# Enigma.Core v1.0.0 Release Notes`: initial-release
  intro, feature overview by category, Compatibility (netstandard2.0/net8.0/net10.0; BouncyCastle
  2.6.2), and Version. No migration guide (brand-new library).
- `src/Enigma.Core/Enigma.Core.csproj` — `<PackageReleaseNotes>` expanded from the PHASE01 placeholder
  to short prose mirroring the RELEASENOTES top, ending with `See RELEASENOTES.md for the full details.`
- `docs/roadmap.md`, `docs/plan/FEATURE-4620.md` — PHASE03 status `TODO → IN PROGRESS → DONE`. The
  base FEATURE-4620 row stays `IN PROGRESS` (PHASE04 remains `TODO`).

**Deleted:** none.

## Acceptance criteria — verification

1. ✅ `README.md`, `RELEASENOTES.md`, `SECURITY.md`, `CLAUDE.md` present and well-formed markdown.
2. ✅ README contains no absolute GitHub URLs and no nuget-breaking relative links; badges resolve.
   The only relative links are the two the plan prescribes — the *What's new* callout → `RELEASENOTES.md`
   and the License badge/line → `LICENSE.md` (both files live at the repo root; `LICENSE.md` is also
   packed into the nupkg). Badges use standard shields.io images linked to the nuget.org package page.
   The Documentation section is prose-only (points to `docs/guides/` without clickable links).
3. ✅ `<PackageReleaseNotes>` mirrors the RELEASENOTES top and ends with `See RELEASENOTES.md for the
   full details.` (verified in the packed nuspec `<releaseNotes>`).
4. ✅ csproj still packs clean with the now-non-empty README; Release build zero-warning; tests green
   (see evidence).

## Build/test evidence

- **Build:** `dotnet build Enigma.Core.slnx -c Release` → **Build succeeded. 0 Warning(s), 0 Error(s)**
  across `netstandard2.0`, `net8.0`, `net10.0` (with `TreatWarningsAsErrors=true`).
- **Tests:** `dotnet test --solution Enigma.Core.slnx -c Release` → **Passed!** total **3254**,
  failed 0, skipped 0 (net8.0 + net10.0 test assemblies).
- **Pack:** `dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts-verify` →
  `Successfully created package 'Enigma.Core.1.0.0.nupkg'`. Inspected the nupkg + nuspec:
  - Embedded `README.md` (now **3789 B**, non-empty) and `LICENSE.md` (1062 B) at the package root.
  - `<version>1.0.0`, `<title>`, `<license type="file">LICENSE.md`, `<readme>README.md`, and the
    finalized `<releaseNotes>` all present and correct.
  - (Verification `./artifacts-verify` directory removed afterwards; not committed.)

## Deviations & follow-ups

- **No deviations from the plan.** All five artifacts were produced as specified; the README was kept
  summary-style with a prose-only docs pointer. A short, API-accurate Quick-start snippet
  (`HashServiceFactory` → `CreateSha256Service()` → `ComputeHashAsync`) was included in the README —
  within the spirit of a summary README and verified against `IHashServiceFactory`/`IHashService`;
  all other samples remain in the `docs/guides/` set.
- **Not packed:** `RELEASENOTES.md`, `SECURITY.md`, and `CLAUDE.md` are repo files only (the nupkg
  packs `README.md` + `LICENSE.md`, per PHASE01). Intentional and consistent with the plan.
- **Remaining phase:** PHASE04 (release runbook `docs/RELEASE.md` + printed pack/tag/push runbook) is
  the last phase before the 1.0.0 cut.
- **Line endings (CRLF):** no line-ending churn observed — `git status` showed only clean content
  diffs on the touched files, no whole-file CRLF↔LF rewrite. `.gitattributes` is present.
  Recommendation-only per the workflow; no action taken.
