# FEATURE-56AA — Repository & solution bootstrap (DONE)

## Summary
Stood up the Enigma.Core repository and solution as infrastructure-only groundwork for FEATURE-4442
and all later work. Initialized a fresh git repo on `main`, brought over the namespace-agnostic config
files verbatim from the old `Enigma.Cryptography` repo, and scaffolded a convention-compliant .NET
solution: an empty multi-targeted `Enigma.Core` library plus an MTP-native xUnit v3 test project with a
single smoke test. No library code beyond the empty project.

## Files/modules touched

### Created — git & config (copied verbatim from `/home/jo/Dev/Enigma.Cryptography`, byte-identical)
- `.gitignore`
- `.gitattributes`
- `.editorconfig`
- `LICENSE.md`

### Created — root docs & build config
- `README.md` — empty (0 bytes)
- `RELEASENOTES.md` — empty (0 bytes)
- `global.json` — SDK `10.0.100` / `rollForward: latestFeature`; `test.runner: Microsoft.Testing.Platform` (MTP)
- `Directory.Build.props` — solution-wide defaults (Authors, Copyright, LangVersion 14, Nullable,
  ImplicitUsings disabled, TreatWarningsAsErrors, EnforceCodeStyleInBuild)
- `Directory.Packages.props` — Central Package Management on; central versions for
  BouncyCastle.Cryptography 2.6.2, System.Buffers 4.6.1, PolySharp 1.15.0, xunit.v3 3.2.2
- `Enigma.Core.slnx` — `.slnx` solution referencing both projects under `/src/` and `/tests/`

### Created — projects
- `src/Enigma.Core/Enigma.Core.csproj` — library, `netstandard2.0;net8.0;net10.0`, PackageId
  `Enigma.Core`, Version 0.1.0, docs generation on, PolySharp (compile-only) on netstandard2.0
- `tests/Enigma.Core.UnitTests/Enigma.Core.UnitTests.csproj` — MTP-native xUnit v3 test project
  (`net10.0`, `OutputType=Exe`, `xunit.v3` only, ProjectReference to the library)
- `tests/Enigma.Core.UnitTests/SmokeTest.cs` — single `[Fact]` proving the toolchain builds/runs green

### Modified — workflow tracking
- `docs/roadmap.md` — FEATURE-56AA status `TODO` → `IN PROGRESS` → `DONE`
- `docs/plan/FEATURE-56AA.md` — status `TODO` → `IN PROGRESS` → `DONE`

## Deviations & follow-ups
- **`dotnet test` invocation:** on the .NET 10 SDK in MTP mode, `dotnet test <solution>` is rejected —
  the solution must be passed as `dotnet test --solution Enigma.Core.slnx`. Non-blocking; noted so
  later devs and any CI use the correct form.
- **No commit performed.** Per the bootstrapping note and the `dev-workflow` "never commit yourself"
  rule, the build initialized the repo on `main` and staging is left to the user — no initial commit
  was made. A suggested initial commit message is printed below.
- **No dev branch.** This bootstrap item ran directly on `main` (there was no `HEAD` to branch from);
  `git init -b main` stood in for the usual branch creation. Every later item follows the normal
  "branch from `HEAD`" rule.
- **Line endings (CRLF):** none observed — `.gitattributes` enforces `* text=auto eol=lf` from the first
  commit, so endings normalize automatically. No action taken (recommendation-only per `dev-workflow`).
- Full NuGet packaging metadata and README/RELEASENOTES content remain deferred to the later release
  feature (`dotnet-release`), as planned.

## Build/test evidence
- **Build:** `dotnet build Enigma.Core.slnx -warnaserror` → `Build succeeded. 0 Warning(s) 0 Error(s)`,
  with `Enigma.Core.dll` produced for `netstandard2.0`, `net8.0`, and `net10.0`, and the test project
  for `net10.0`.
- **Test:** `dotnet test --solution Enigma.Core.slnx` (MTP) → `Passed! total: 1, failed: 0, succeeded: 1,
  skipped: 0`. Smoke test green.
- **Empty files:** `wc -c README.md RELEASENOTES.md` → both `0` bytes.
- **Config copy:** `cmp -s` confirmed `.gitignore`, `.gitattributes`, `.editorconfig`, `LICENSE.md`
  byte-identical to the source repo.

## Acceptance criteria — all met
1. ✅ Git repo initialized on `main`; four copied config files present and byte-identical to source.
2. ✅ `README.md` and `RELEASENOTES.md` exist and are empty (0 bytes).
3. ✅ `Enigma.Core.slnx` loads; `dotnet build` succeeds with zero warnings across `netstandard2.0`,
   `net8.0`, `net10.0`.
4. ✅ `dotnet test` runs via MTP and the smoke test passes green.
5. ✅ Roadmap + plan present; this completion doc written.
