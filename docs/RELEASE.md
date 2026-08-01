# Release runbook

Reusable checklist for publishing a new **Enigma.Core** version to NuGet. Only the packable library
project (`src/Enigma.Core/`) is published; any Tools / CLI / Desktop projects in the solution ship as source.

Replace `X.Y.Z` with the version being released (e.g. `1.0.0`) throughout. The version lives in
`src/Enigma.Core/Enigma.Core.csproj` (`<Version>`); a CLI or app in the same solution may carry its own
independent `<Version>` and is not published to NuGet.

## 1. Pre-release checks

Run from the repository root, on the branch that will be merged:

- [ ] `<Version>X.Y.Z</Version>` set in `src/Enigma.Core/Enigma.Core.csproj`.
- [ ] `RELEASENOTES.md` has a top `X.Y.Z` section describing the release (newest-first; any `(unreleased)`
      heading renamed to `X.Y.Z`).
- [ ] `<PackageReleaseNotes>` in the library csproj summarizes the release and points to `RELEASENOTES.md`.
- [ ] README badges and the "what's new" callout reflect `X.Y.Z`.
- [ ] `<TargetFrameworks>` reflect the `net8.0` + `net10.0` policy (`netstandard*` preserved); any change was
      proposed/confirmed and logged in `RELEASENOTES.md` *Compatibility*.
- [ ] Clean, warning-free build across all TFMs:
      ```bash
      dotnet build Enigma.Core.slnx -c Release
      ```
- [ ] Full test suite green:
      ```bash
      dotnet test Enigma.Core.slnx -c Release
      # If the test apphost can't find the runtime, prefix: DOTNET_ROOT=~/.dotnet
      ```
- [ ] README samples and any CLI reference verified against the built version.

## 2. Merge to the default branch

Merge the release branch into the default (published) branch — `main` — via a pull request (or
fast-forward), then check it out locally:

```bash
git switch main
git pull
```

## 3. Tag the release

Match the repo's existing tag convention — run `git tag` to see how prior releases were tagged (bare `X.Y.Z`
vs. `vX.Y.Z`). This repo has no tags yet, so use a **bare** `X.Y.Z` tag. Tag the merge commit and push the tag:

```bash
git tag X.Y.Z
git push origin X.Y.Z
```

## 4. Pack

`GeneratePackageOnBuild` is **off** for this library, so no `.nupkg` is produced on an ordinary build — pack
explicitly in Release to get the artifact you publish:

```bash
dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts
```

This writes `./artifacts/Enigma.Core.X.Y.Z.nupkg`. Confirm the version in the filename matches the tag, and
(optionally) inspect the package contents — it should bundle `README.md` and `LICENSE.md` and declare the
expected dependency floors (BouncyCastle.Cryptography 2.7.0; System.Buffers on netstandard2.0).

## 5. Push to NuGet

Publish with a NuGet API key that has push rights for the `Enigma.Core` package:

```bash
dotnet nuget push ./artifacts/Enigma.Core.X.Y.Z.nupkg \
  --api-key <NUGET_API_KEY> \
  --source https://api.nuget.org/v3/index.json
```

This release ships no symbol package (SourceLink / `snupkg` are not configured), so `dotnet pack` emits only
the `.nupkg` — that single file is what you push. The API key is a secret — never commit or echo it.

## 6. Post-publish verification

- [ ] The package page shows the new version: <https://www.nuget.org/packages/Enigma.Core> (indexing can
      take a few minutes).
- [ ] The README NuGet badge resolves to `X.Y.Z` (shields.io caches briefly).
- [ ] A scratch project can restore the new version:
      ```bash
      dotnet add package Enigma.Core --version X.Y.Z
      ```
- [ ] The GitHub release/tag is present and its notes match `RELEASENOTES.md`.
