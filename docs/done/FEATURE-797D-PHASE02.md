# FEATURE-797D-PHASE02 — Release v1.1.0

**Status:** DONE
**Type:** FEATURE (multi-phase, phase 2 of 2 — final)
**Branch:** `feature/feature-797d-phase02-release-110` (cut from
`feature/feature-797d-phase01-bouncycastle-270` @ `3ae831b`)

## Summary

Cut the **v1.1.0** release on top of PHASE01's BouncyCastle 2.7.0 upgrade, following `dotnet-release`'s
**routine release** path (a published version already exists): version bump, release notes,
`PackageReleaseNotes`, what's-new callout, the version-consistency doc refreshes, and a local
pack-verify of the real artifact.

1.1.0 is a **minor**, not a patch: no public API is added, removed or changed and the library's own
behaviour is unchanged, but the runtime dependency floor moves to `>= 2.7.0` — which is
consumer-visible, because anyone pinned to BouncyCastle 2.6.x must upgrade. Per decision 6 there is
**no *Breaking Changes & Migration* section**; the raised floor is recorded under *Dependencies* plus
a *Compatibility* line.

**Tagging and publishing remain the maintainer's.** This phase stops at pack-verify — the runbook is
printed, never run, and the NuGet API key never appears in the repo or in any output.

## Files/modules touched

**Modified**
- `src/Enigma.Core/Enigma.Core.csproj` — `<Version>` 1.0.0 → **1.1.0**; `<PackageReleaseNotes>`
  rewritten to mirror the new notes section, ending `See RELEASENOTES.md for the full details.`
- `RELEASENOTES.md` — **prepended** a `# Enigma.Core v1.1.0 Release Notes` section
  (*Dependencies* · *Compatibility* · *Version*). The 1.0.0 section below it is **unmodified** —
  including its `Built on BouncyCastle.Cryptography 2.6.2` line, which is a correct historical
  statement of what 1.0.0 shipped with.
- `README.md` — what's-new callout `1.0` → `1.1` with a one-line highlight; *Installation* line
  `built on BouncyCastle 2.6.2` → `2.7.0`.
- `SECURITY.md` — supported-versions table `1.0.x` → `1.1.x`.
- `CLAUDE.md` — runtime dependency `2.6.2` → `2.7.0`.
- `docs/RELEASE.md` — expected dependency floor `2.6.2` → `2.7.0`.
- `CLAUDE.md` (doc-freshness sweep) — dropped the version qualifier from *"no `AddEnigmaCore`
  DI-registration helper **in 1.0.0**"*; the statement is version-independent and no longer needs an
  edit each release.
- `docs/roadmap.md` — `PHASE02` `TODO` → `IN PROGRESS` → `DONE`; the `FEATURE-797D` item row
  `IN PROGRESS` → **`DONE`** (final phase).
- `docs/plan/FEATURE-797D.md` — item and PHASE02 statuses → `DONE`.

**Created**
- `docs/done/FEATURE-797D-PHASE02.md` — this completion record.

**Not modified (deliberately)**
- The 13 guides under `docs/guides/` — none names a BouncyCastle version or a package version, so
  they are untouched and **the snippet-verification gate did not fire this release**.
- `README.md` badges (the NuGet-version badge self-tracks; no Downloads badge — house set) and the
  supported-TFM list (the TFM set did not move: `netstandard2.0;net8.0;net10.0`, already the
  normalized `netstandard*` + net8/net10 LTS pair).
- Historical `docs/plan/` and `docs/done/` records (decision 8) — dated statements of what was true
  when that work shipped.
- No `CHANGELOG.md` was added — `RELEASENOTES.md` is the single release-notes source.
- No `src/` behaviour change, no tag, no publish.

## Package-metadata check

All 12 packable-library properties confirmed present and correct; `GeneratePackageOnBuild` is absent
(off); and **no symbol property has crept in** — `IncludeSymbols`, `SymbolPackageFormat`,
`PublishRepositoryUrl` and `EmbedUntrackedSources` are all absent, so the release ships the `.nupkg`
only.

## Pack-verify findings

```bash
dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts-verify
  → Successfully created package 'artifacts-verify/Enigma.Core.1.1.0.nupkg'
```

| Check | Result |
|---|---|
| `.nupkg` version | **1.1.0** ✔ matches the release |
| Verify directory contents | `Enigma.Core.1.1.0.nupkg` **and nothing else** — no `.snupkg` ✔ |
| `README.md` embedded | ✔ present, **3 587 bytes** (non-empty), and is the *updated* README — carries the 1.1 callout and `built on BouncyCastle 2.7.0` |
| `LICENSE.md` embedded | ✔ present, 1 062 bytes |
| nuspec `<version>` | `1.1.0` ✔ |
| nuspec `<title>` | `Enigma.Core — .NET Cryptography Library` ✔ |
| nuspec `<license type="file">` | `LICENSE.md` ✔ |
| nuspec `<readme>` | `README.md` ✔ |
| nuspec `<releaseNotes>` | ✔ mirrors the new 1.1.0 notes section |
| Lib assemblies | `lib/{netstandard2.0,net8.0,net10.0}/Enigma.Core.dll` + `.xml` (XML docs ship on all three TFMs) ✔ |

**Observed per-TFM dependency floors** — exactly as expected:

| Target framework | Dependencies |
|---|---|
| `net8.0` | `BouncyCastle.Cryptography >= 2.7.0` |
| `net10.0` | `BouncyCastle.Cryptography >= 2.7.0` |
| `.NETStandard2.0` | `BouncyCastle.Cryptography >= 2.7.0`, `System.Buffers >= 4.6.1` |

`PolySharp` correctly does **not** appear in any dependency group (compile-only,
`PrivateAssets=all`), and `System.Buffers` appears on `netstandard2.0` only.

**The verify directory was then deleted** — it is a scratch artifact and is never committed.

## Build/test evidence

```
dotnet build Enigma.Core.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0

dotnet test --solution Enigma.Core.slnx -c Release
  Test run summary: Passed!
  total: 3280   failed: 0   succeeded: 3280   skipped: 0
  → net8.0 and net10.0
```

Re-verified in this phase (not carried over from PHASE01), after the version bump and all
documentation edits.

## Acceptance criteria

1. ✔ `<Version>1.1.0</Version>` and a `<PackageReleaseNotes>` mirroring the new notes section.
2. ✔ `RELEASENOTES.md` has a top 1.1.0 section with *Dependencies* / *Compatibility* / *Version*,
   recording **both** transitions (`BouncyCastle.Cryptography 2.6.2 → 2.7.0`;
   `coverlet.collector 6.0.4 → 10.0.1`, test-only); the 1.0.0 section is preserved unmodified below.
3. ✔ `README.md` (callout + BouncyCastle line), `SECURITY.md`, `CLAUDE.md` and `docs/RELEASE.md` are
   all consistent at 1.1.0 / BouncyCastle 2.7.0; badges and the TFM list unchanged.
4. ✔ Release build clean with 0 warnings; full suite green — 3280/3280.
5. ✔ Pack-verify passed on every point above; the verify directory was deleted.
6. ✔ The tag / pack / push runbook is **printed, not run**, using the bare `1.1.0` tag format
   (matching the existing `1.0.0` tag, confirmed via `git tag`).
7. ✔ This document.
8. ✔ The item's roadmap row flips to `DONE` alongside PHASE02.

## Deviations & follow-ups

- **No deviation from the plan.** Every predicted edit applied cleanly; the pack-verify produced
  exactly the expected artifact and dependency floors, with no metadata surprises.
- **Line endings:** no CRLF noise in any touched file — all LF, `.gitattributes` already enforces
  `eol=lf`. No recommendation applies.
- **Release stops here by design.** The maintainer runs the printed runbook: pre-flight, merge to
  `main`, bare `1.1.0` tag, publish `dotnet pack` into `./artifacts`, `dotnet nuget push`.
- **Carried forward from PHASE01** (unchanged by this phase): coverage collection is not wired under
  the MTP-native runner, so the `coverlet.collector` 6 → 10 transition is verified by restore +
  build + a green suite rather than an actual coverage run; and the `Directory.Packages.props` header
  comment is still stale. Both are pre-existing and out of this item's scope.
- **SLH-DSA (FIPS 205)** remains recorded as out of scope — BouncyCastle 2.7.0 exposes it, and it
  would round out the PQC category, but it is a full service + factory + enum + guide + test-suite
  build and belongs to its own FEATURE.
