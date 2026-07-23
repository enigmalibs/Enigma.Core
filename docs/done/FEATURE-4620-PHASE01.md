# FEATURE-4620 PHASE01 — Package metadata & build config + license check

**Status:** DONE

## Summary

Turned `src/Enigma.Core/Enigma.Core.csproj` into a complete, valid NuGet package definition for the
first public release, bumped the version to **1.0.0**, wired the README and LICENSE into the package,
and verified licensing and dependency freshness. `dotnet pack` now produces a well-formed
`Enigma.Core.1.0.0.nupkg` with both files embedded and correct metadata.

## Files/modules touched

**Modified**

- `src/Enigma.Core/Enigma.Core.csproj`
  - `<Version>` `0.1.0` → **`1.0.0`**.
  - Added `<Title>`, `<Description>` (fresh one-paragraph feature summary — no reference to any prior
    library), `<PackageTags>`, `<PackageReadmeFile>README.md</PackageReadmeFile>`,
    `<PackageLicenseFile>LICENSE.md</PackageLicenseFile>`, `<RepositoryUrl>`, `<RepositoryType>git`,
    `<PackageProjectUrl>`, and a short placeholder `<PackageReleaseNotes>` (finalized in PHASE03).
  - Added the packaging `<ItemGroup>` packing `..\..\README.md` and `..\..\LICENSE.md` to the nupkg root.
  - Kept `<GenerateDocumentationFile>true`; did **not** add `GeneratePackageOnBuild` (stays off).
- `Directory.Packages.props` — PolySharp `1.15.0` → **`1.16.0`** (see Dependency freshness below).
- `README.md` — added a minimal placeholder (was empty); see Deviations.
- `docs/roadmap.md`, `docs/plan/FEATURE-4620.md` — FEATURE-4620 + PHASE01 flipped to `IN PROGRESS`,
  then PHASE01 to `DONE` on completion.

**Created**

- `docs/done/FEATURE-4620-PHASE01.md` (this file).

## License check (findings)

- **`LICENSE.md`** — present at the repo root, MIT-equivalent text, dated **2026** (`Copyright (c)
  2026 Josué Clément`). Now packed into the nupkg root (verified: 1062 bytes present in the package)
  and referenced via `<PackageLicenseFile>` (the `<PackageLicenseFile>` route, not the SPDX
  expression, per the plan). The README license badge will target `LICENSE.md` (badge added in PHASE03) — consistent.
- **Third-party runtime dependency licenses** — all MIT / MIT-compatible and safe to redistribute:
  - `BouncyCastle.Cryptography` **2.6.2** — MIT. Redistributed (nuspec dependency on all three TFMs).
  - `System.Buffers` **4.6.1** — MIT. Redistributed on **netstandard2.0 only** (nuspec confirms it is
    listed only under the `.NETStandard2.0` group; framework-provided on net8.0/net10.0).
  - `PolySharp` **1.16.0** — MIT. **Compile-only** (`PrivateAssets="all"`, netstandard2.0 only);
    confirmed **not** in the nuspec `<dependencies>`, so it is not redistributed.
  - `xunit.v3`, `coverlet.collector` — test-only; not part of the shipped package.
- **Conclusion:** all shipped/compile-time dependencies are MIT-compatible; no license conflict for a
  1.0.0 public release.

## Dependency freshness

`dotnet list package --outdated` reported a single update: **PolySharp 1.15.0 → 1.16.0**
(netstandard2.0 only). Applied — it is a straightforward, non-coupled minor bump of a compile-only
polyfill (`PrivateAssets=all`), which cannot alter the shipped package contents (it is absent from the
nuspec dependencies). BouncyCastle (2.6.2) and System.Buffers (4.6.1) were already at their resolved
latest; no other changes. Zero-warning Release build re-verified after the bump.

- `PolySharp`: `1.15.0` → `1.16.0`

## Deviations & follow-ups

- **Placeholder README (bridge for pack).** The plan packs `README.md` in PHASE01 but only populates
  it in PHASE03. NuGet rejects an empty readme (`error NU5040: The readme file 'README.md' is empty.`),
  so `dotnet pack` failed against the empty file. Added a minimal placeholder `README.md` (title +
  one-line intro + a note that the full README arrives in PHASE03) purely to satisfy NuGet's non-empty
  check and let PHASE01 meet its pack acceptance criterion. **PHASE03 fully replaces this file** with
  the summary README (badges, feature overview, installation, docs pointers). This matches the plan's
  own PHASE03 wording ("README now non-empty"); no scope change.
- **Line endings (CRLF):** no line-ending churn observed — `git status` showed only clean content
  diffs on the five touched files, no whole-file CRLF↔LF rewrite. `.gitattributes` is present.
  Recommendation-only per the workflow; no action taken.

## Build/test evidence

- **Build:** `dotnet build Enigma.Core.slnx -c Release` → **Build succeeded. 0 Warning(s), 0 Error(s)**
  across `netstandard2.0`, `net8.0`, `net10.0` (with `TreatWarningsAsErrors=true`).
- **Tests:** `dotnet test --solution Enigma.Core.slnx -c Release` → **Passed!** total **3254**,
  failed 0, skipped 0 (net8.0 + net10.0 test assemblies).
- **Pack:** `dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts-verify` →
  `Successfully created package 'Enigma.Core.1.0.0.nupkg'`. Inspected with `unzip -l` + nuspec:
  - Embedded `README.md` (345 B) and `LICENSE.md` (1062 B) at the package root.
  - `id=Enigma.Core`, `version=1.0.0`, title/description/tags/repository/projectUrl/readme/license
    all as configured; `<license type="file">LICENSE.md</license>`, `<readme>README.md</readme>`.
  - Dependencies: BouncyCastle 2.6.2 (all TFMs), System.Buffers 4.6.1 (netstandard2.0 only);
    PolySharp absent (compile-only).
  - (Verification `./artifacts-verify` output directory removed afterwards; not committed.)

## Acceptance criteria — verification

1. ✅ `dotnet pack …` produces `Enigma.Core.1.0.0.nupkg` with README.md + LICENSE.md embedded
   (verified by inspecting the nupkg).
2. ✅ Zero-warning Release build across netstandard2.0 / net8.0 / net10.0; full test suite green (3254).
3. ✅ License-check findings recorded (above).
