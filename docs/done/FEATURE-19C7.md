# FEATURE-19C7 — Release v2.0.0

**Status:** DONE
**Branch:** `feature/feature-19c7-release-200`
**Plan:** `docs/plan/FEATURE-19C7.md` (single-phase)

## Summary

Cut **Enigma.Core 2.0.0**, the library's first MAJOR release. It carries one breaking change spanning two
items — RSA key material now crosses the public surface as an `RsaKey` handle rather than PEM text, in
both the public-key module (FEATURE-6852) and the certificate module (FEATURE-57A9) — plus two additive
features: the PQC key PEM services (FEATURE-5413) and the Checksum module (FEATURE-D254).

This followed the `dotnet-release` skill's **routine release** path: version, notes, callout, pack-verify,
runbook. No `src/` behaviour changed, no test changed, and no dependency moved — the BouncyCastle floor
stays at 2.7.0 and the target frameworks stay `netstandard2.0;net8.0;net10.0`, so there was no
target-framework normalization and no *Dependencies* section in the notes.

The release-note migration copy was **consolidated, not re-derived**: the seven-row `IPublicKeyService`
removal table and the five-row `IX509CertificateService` before/after table came from
`docs/done/FEATURE-6852-PHASE02.md` and `docs/done/FEATURE-57A9.md` as the plan directs. The two
*passphrase moves to the import* sections in those documents were **merged into one** section covering
both services, since they made the same point twice. The *New Features* copy was written here from the
shipped surface, cross-checked against both plans.

## Files/modules touched

### Modified

| File | Change |
|---|---|
| `src/Enigma.Core/Enigma.Core.csproj` | `<Version>` 1.1.0 → **2.0.0**; `<PackageReleaseNotes>` rewritten to lead with the breaking change; `<Description>` extended with the `RsaKey` handle, per-family PQC key PEM and the CRC variants; `<PackageTags>` gained `pem crc crc16 crc32 checksum` |
| `RELEASENOTES.md` | **2.0.0 section prepended** (+232 lines): *Breaking Changes & Migration*, *New Features*, *Compatibility*, *Version*. The 1.1.0 and 1.0.0 sections are byte-identical below it |
| `README.md` | what's-new callout `1.1` → `2.0`, leading with the breaking change and naming both additions |
| `SECURITY.md` | supported-versions table `1.1.x` → `2.0.x` (see *Decisions* below) |
| `docs/guides/README.md` | the PQC index line now mentions key PEM import/export — FEATURE-5413 added a whole `## PEM serialization` section to `pqc.md` that the one-liner did not reflect |
| `docs/guides/pqc.md` | **doc sweep** — the intro's "works entirely in raw `byte[]` values" clause now scopes that claim to the cryptographic operations and points at the PEM services (prose only; no snippet touched) |
| `docs/RELEASE.md` | the stale "This repo has no tags yet, so use a **bare** `X.Y.Z` tag" sentence corrected — prior releases *are* tagged bare (`1.0.0`, `1.1.0`), so the convention continues rather than being chosen |
| `docs/roadmap.md` | FEATURE-19C7 → `IN PROGRESS` → `DONE`. The table was re-padded twice in flight — `IN PROGRESS` widened the Status column 6 → 11, invalidating every row's padding, and `DONE` shrank it back — so the committed diff is a clean one-line status change |
| `docs/plan/FEATURE-19C7.md` | status → `IN PROGRESS` → `DONE` |

### Verified unchanged, deliberately

- **README badges** — the house set of two (NuGet version, MIT licence). No Downloads badge, per FEATURE-28C7.
- **README TFM line** — "Targets **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**; built on
  BouncyCastle 2.7.0" is still exact; the TFM set did not move this release.
- **README Features list** — the *Checksums* bullet FEATURE-D254 added reads true against the shipped
  surface; `docs/guides/README.md`'s *Checksums* entry likewise.
- **No `CHANGELOG.md`** added — `RELEASENOTES.md` remains the single notes source.
- **No symbol properties** — `IncludeSymbols`, `SymbolPackageFormat`, `PublishRepositoryUrl` and
  `EmbedUntrackedSources` are absent from both the csproj and `Directory.Build.props`, and
  `GeneratePackageOnBuild` is absent (off). All 12 packable-library properties are present.
- **`CLAUDE.md`** and `docs/RELEASE.md:63` — both name BouncyCastle 2.7.0, which is unchanged, so both
  stay as written (out of scope per the plan).
- **`src/`, `tests/`** — not touched. No behaviour or test change in a release phase.

## Decisions

- **SECURITY.md support window: `2.0.x` only.** The 1.1.x row was replaced rather than kept alongside.
  The section's own prose already reads "Security fixes are provided for the latest released version", so
  a second supported row would have contradicted the sentence directly above the table. Consumers still
  on 1.x are covered by the release notes' explicit assurance that their **key files** keep working, which
  is the migration blocker a support window would otherwise be papering over. Recorded per plan step 4.
- **Notes section order puts *Breaking Changes & Migration* first**, ahead of *New Features*. The
  `dotnet-release` skill's default order lists *New Features* first; the plan overrides it for this
  release, and the plan wins — a consumer opening 2.0.0's notes needs the break before the additions.
- **The two completion docs' duplicate passphrase sections were merged.** Both carried a
  "The passphrase is supplied once, at the import" subsection making the same point for its own service.
  The notes carry one such section covering both, with the RSA example and the certificate example under it.

## Deviations & follow-ups

- **Plan line numbers had drifted; the content had not.** The plan cites `README.md:46` for the TFM
  sentence (actually line 52) and `SECURITY.md:15` (correct). Every *substantive* claim the plan makes
  about the current state held: `<Version>1.1.0</Version>`, the callout at line 11, and the stale
  `docs/RELEASE.md` tag sentence. No reconciliation was needed.
- **`docs/guides/pqc.md`'s intro was imprecise** — it said the PQC services give you "a small, focused
  interface that works entirely in raw `byte[]` values", which predated the PEM services that same guide
  now documents in a full `## PEM serialization` section (58 `Pem` mentions). Every *snippet* in the
  guide was correct; only that one prose clause was stale. Raised in the documentation-freshness sweep,
  accepted, and **fixed in this dev's commit** — the claim is now scoped to the cryptographic operations
  and links to the PEM section. No snippet was touched, so the coverage table below still stands.
- **Line endings:** no CRLF churn. Every one of the eight touched files is LF-only (verified with
  `grep -U $'\r'`); the repo normalizes via `.gitattributes`. No action taken — recommendation-only per
  the workflow, and there is nothing to recommend.
- **Tagging and publishing remain the maintainer's.** This item stops at printing the runbook. No
  `git tag`, no `dotnet nuget push`, and no pack into a real `./artifacts` was run. The NuGet API key
  appears nowhere in the repo or in this dev's output.
- **Follow-up (not done here):** the guides have no compile harness, so the snippet-verification gate
  below is a point-in-time check that must be re-run whenever the public surface moves. A permanent
  doc-sample test project remains the known alternative — considered and declined at 1.0.0
  (FEATURE-4620), still declined.

## Snippet-verification coverage

Acceptance criterion 5. Every code fence in the four guides this release touches was verified **by
compilation against the shipped 2.0.0 API**, not by eye: each was assembled into a throwaway
`net10.0` library project referencing `src/Enigma.Core/Enigma.Core.csproj`, and the project was built.
The scratch projects were discarded.

**Coverage: 47 snippets · 119 distinct API symbols · 0 mismatches · 0 uncertain**

| Target | Snippets | Symbols | Mismatch | Uncertain |
|---|---|---|---|---|
| `docs/guides/public-key.md` | 11 | 29 | 0 | 0 |
| `docs/guides/certificates.md` | 16 | 48 | 0 | 0 |
| `docs/guides/pqc.md` | 15 | 31 | 0 | 0 |
| `docs/guides/checksum.md` | 5 | 11 | 0 | 0 |
| **Total** | **47** | **119** | **0** | **0** |

The 47 fences are not all compilable programs, and were verified in three distinct ways:

| Kind | Count | How verified |
|---|---|---|
| Self-contained samples | 26 | Compiled with **only their own `using` directives**, so a copy-paste genuinely works. 0 errors, 0 warnings |
| Fragments continuing a section | 7 | Compiled with the section's established context injected as method parameters (e.g. `certificates`, `leafPem`, `caKey`). 0 errors |
| Declaration listings (interface/enum extracts) | 12 | Cross-checked member-by-member against `src/` — see below |
| Deliberate 1.x "before" blocks | 2 | Asserted **not** to compile (see below) |

**The 12 declaration listings match `src/` exactly**, checked against the real files:
`RsaOaepHash` (4 members) · `RsaSignatureAlgorithm` (4, in `src/Enigma.Core/RsaSignatureAlgorithm.cs`) ·
`IPublicKeyService` (7 members, verbatim including default parameter values) · `RsaKey`'s 6 public
members · `X509KeyUsage` (10 members, in order) · `IMLKemServiceFactory` / `IMLDsaServiceFactory`
`Create*` signatures · `IMLKemService` (3) · `IMLDsaService` (3) · `IMLDsaPemServiceFactory` /
`IMLKemPemServiceFactory` · `IMLDsaPemService` (5) · `IMLKemPemService` (5) · `IChecksumService` (5).

**The 2 migration "before" blocks were asserted to fail**, which is what makes the guides' before/after
contrast trustworthy rather than decorative. Compiling them confirms every removed member is genuinely
gone from the shipped surface:

```
public-key.md  'IPublicKeyService' does not contain a definition for 'GenerateRsaKeyPair'   (CS1061)
               No overload for method 'Sign' takes 4 arguments                              (CS1501)
               No overload for method 'DecryptOaep' takes 4 arguments                       (CS1501)
               Argument 3: cannot convert from 'string' to '…RsaKey'                        (CS1503)

certificates.md  No overload for 'GenerateSelfSignedCertificate' takes 7 arguments          (CS1501)
                 No overload for 'GenerateCertificateSigningRequest' takes 4 arguments      (CS1501)
                 No overload for 'IssueCertificate' takes 8 arguments                       (CS1501)
```

One fence (`certificates.md` #16) shows the 1.x and 2.0.0 `ImportPkcs12` forms side by side and cannot
compile as a unit — it declares `key` and `certPem` twice by design. Its 2.0.0 half was compiled
separately; its 1.x half is covered by the assertion above.

## Build/test evidence

```
dotnet build Enigma.Core.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0

dotnet test --solution Enigma.Core.slnx -c Release
  Test run summary: Passed!
  total: 3902   failed: 0   succeeded: 3902   skipped: 0
  duration: 9s 687ms
  → net8.0 (9s 553ms) and net10.0 (9s 286ms)
```

`TreatWarningsAsErrors=true` and `EnforceCodeStyleInBuild=true` are in force, so this is a genuine
zero-warning build. Test count is **3902**, unchanged from FEATURE-D254 — this phase adds no tests, by
design (a release phase changes no `src/` behaviour).

### Pack-verify

```
dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts-verify
  → Successfully created package 'artifacts-verify/Enigma.Core.2.0.0.nupkg'
```

| Check | Result |
|---|---|
| `.nupkg` version | **2.0.0** — matches the release |
| Verify dir contents | **exactly one file**, `Enigma.Core.2.0.0.nupkg` (273 324 bytes). **No `.snupkg`** |
| `README.md` embedded | yes — **4 247 bytes, 85 lines**, first line `# Enigma.Core`; the `What's new in 2.0` callout is present in the packed copy |
| `LICENSE.md` embedded | yes — 1 060 bytes, `Copyright (c) 2026 Josué Clément` |
| nuspec `<version>` | `2.0.0` |
| nuspec `<title>` | `Enigma.Core — .NET Cryptography Library` |
| nuspec `<license type="file">` | `LICENSE.md` |
| nuspec `<readme>` | `README.md` |
| nuspec `<releaseNotes>` | present, opens `BREAKING: RSA key material now crosses the public surface as a reusable RsaKey handle…` |
| nuspec `<repository>` | `type="git"`, correct url, `commit="b6eb6bf…"` |
| nuspec `<tags>` | includes the new `pem crc crc16 crc32 checksum` |
| nuspec `<description>` | mentions PQC key PEM import/export **and** CRC checksums |
| `lib/` layout | three TFMs, each with `Enigma.Core.dll` + `Enigma.Core.xml` (XML docs ship) |

**Observed per-TFM dependency floors** — exactly as expected:

| Target framework | Dependencies |
|---|---|
| `net8.0` | `BouncyCastle.Cryptography >= 2.7.0` |
| `net10.0` | `BouncyCastle.Cryptography >= 2.7.0` |
| `.NETStandard2.0` | `BouncyCastle.Cryptography >= 2.7.0`, `System.Buffers >= 4.6.1` |

`System.Buffers` appears on `netstandard2.0` only, as intended, and **PolySharp is correctly absent from
every group** — it is compile-only (`PrivateAssets=all`) and must not be a consumer dependency.

`./artifacts-verify` was **deleted** after inspection and is not committed.

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | csproj at `2.0.0`; `PackageReleaseNotes` leads with the breaking change; `Description` + `PackageTags` mention PQC key PEM **and** CRC checksums | `<Version>2.0.0</Version>`; the notes open `BREAKING: RSA key material…`; description mentions "key PEM import/export" and "CRC checksums"; tags gained `pem crc crc16 crc32 checksum` — all four re-confirmed **from the packed nuspec**, not just the csproj |
| 2 | Top 2.0.0 section with *Breaking Changes & Migration*, *New Features*, *Compatibility*, *Version*; 1.1.0/1.0.0 preserved unmodified; *New Features* covers FEATURE-5413 **and** FEATURE-D254 | all four sections present in that order; `git diff RELEASENOTES.md` is **+232/-0** — purely additive, so the older sections are untouched; *New Features* has one subsection per item |
| 3 | *Breaking Changes* lists every removed `IPublicKeyService` member with its replacement, every changed `IX509CertificateService` member, states nothing was deprecated, and documents the PEM write-format change with the read guarantee | the seven-row and five-row tables; "Nothing is marked `[Obsolete]` … there is no deprecation window"; the *Encrypted private-key PEMs are now written as PBES2 — reading is unchanged* section, including that 1.x also reads PBES2, so the break is API-only |
| 4 | README callout, SECURITY.md and `docs/guides/README.md` consistent at 2.0.0; both list the Checksum module; badges and TFM list unchanged; `docs/RELEASE.md` tag sentence reflects the real tags | callout → `What's new in 2.0`; table → `2.0.x`; README *Checksums* bullet and guide-index *Checksums* entry both verified true; two badges unchanged; TFM line unchanged and still exact; `git tag -l` → `1.0.0`, `1.1.0`, and the sentence now says so |
| 5 | Every snippet in the three rewritten guides **and** `checksum.md` compiles against the shipped API | see *Snippet-verification coverage* — 47 snippets, 119 symbols, 0 mismatches, 0 uncertain; 33 compiled units built with 0 errors / 0 warnings |
| 6 | Release build clean, zero warnings, three TFMs; suite green on net8.0 and net10.0 | `0 Warning(s) 0 Error(s)`; **3902/3902** passed |
| 7 | Pack-verify passes on every listed check; verify dir deleted | see *Pack-verify* — every row green, `.nupkg` only, floors as expected, directory deleted |
| 8 | Runbook printed, not run, with the bare `2.0.0` tag | printed to the console at the end of this dev; no tag, pack-to-`artifacts`, or push was executed |
| 9 | This document records files changed, pack-verify findings incl. per-TFM floors, the SECURITY.md decision, maintainer ownership of tag/publish, and the snippet coverage table | this file |
| 10 | Roadmap row flips to `DONE` | `docs/roadmap.md` — `FEATURE-19C7 … DONE` |

## Documentation freshness sweep

Run before the commit message was printed. Two concrete candidates were offered — the `docs/guides/pqc.md`
intro clause and a re-read of `CLAUDE.md` — plus skip and name-your-own options.

**Accepted: the `pqc.md` intro clause.** Fixed in this dev's commit (see *Deviations*).

**Not taken: `CLAUDE.md`.** Its architecture section already lists the Checksum module and the PQC PEM
services, and its BouncyCastle 2.7.0 reference is unchanged this release — the sweep found nothing
actually wrong with it, and the plan puts it out of scope for that reason.
