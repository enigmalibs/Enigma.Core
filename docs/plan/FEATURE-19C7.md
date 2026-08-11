# FEATURE-19C7 — Release v2.0.0

**Status:** TODO (single-phase)
**Type:** FEATURE
**Branch (at build time):** `feature/feature-19c7-release-200` — cut from current `HEAD`.

## Objective

Cut **Enigma.Core 2.0.0**: the first MAJOR release, carrying PQC PEM services (FEATURE-5413), the
`RsaKey` handle across the public-key and certificate modules (FEATURE-6852, FEATURE-57A9), and the
new Checksum module (FEATURE-D254).

Follows the `dotnet-release` skill's **routine release** path (a published version already exists),
which is a single phase: version, notes, callout, dependency log, pack-verify, runbook. This release
differs from 1.1.0 in one important way — it **does** need a *Breaking Changes & Migration* section.

**Depends on FEATURE-5413, FEATURE-6852, FEATURE-57A9 and FEATURE-D254 all being `DONE`.** The
completion docs of **FEATURE-6852-PHASE02 and FEATURE-57A9** carry ready-to-paste release-note copy for
the breaking changes — do not re-derive it. **FEATURE-5413 and FEATURE-D254 produce no such copy**; the
*New Features* section is written here, from the surface listed in design step 2 (cross-check against
the "Public surface added by this item" section of `docs/plan/FEATURE-5413.md` and
`docs/plan/FEATURE-D254.md`, and against the shipped types).

## Context & constraints

- Current published version **1.1.0**; tags use the **bare** format (`1.0.0`, `1.1.0`), so this one is
  `2.0.0`.
- Runtime dependency stays **BouncyCastle.Cryptography 2.7.0** — no dependency transition this
  release. Target frameworks stay `netstandard2.0;net8.0;net10.0`.
- `RELEASENOTES.md` is the single release-notes source; **do not** add a `CHANGELOG.md`.
- README badge set is the house set (NuGet-version badge self-tracks; **no** Downloads badge — see
  FEATURE-28C7). Do not add symbol-package properties.
- Tagging and publishing remain the **maintainer's**; this item stops at printing the runbook.

## Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Enigma.Core.csproj` | `<Version>` 1.1.0 → **2.0.0**; rewrite `<PackageReleaseNotes>`; refresh `<Description>` and `<PackageTags>` for the new PQC PEM and CRC-checksum capabilities |
| `RELEASENOTES.md` | **prepend** a 2.0.0 section, including *Breaking Changes & Migration* |
| `README.md` | what's-new callout `1.1` → `2.0` (line 11); check line 46's TFM/BouncyCastle sentence still reads true |
| `SECURITY.md` | supported-versions table `1.1.x` → `2.0.x` (line 15) |
| `docs/guides/README.md` | index descriptions refreshed if the PQC or public-key entries changed |
| `docs/RELEASE.md` | lines 44-45 claim "This repo has no tags yet, so use a **bare** `X.Y.Z` tag" — stale: `git tag -l` returns `1.0.0` and `1.1.0`. Correct it to state that prior releases are tagged bare and the convention continues |

**Out of scope**
- `CLAUDE.md:68` and `docs/RELEASE.md:63` — both name BouncyCastle **2.7.0**, which is unchanged;
  touch them only if something else in them went stale.
- Any `src/` behaviour change. Any test change. Any tag. Any publish.
- Historical `docs/plan/` and `docs/done/` records — dated statements of what was true when that work
  shipped; they stay as written.
- Re-deriving migration content: FEATURE-6852-PHASE02 and FEATURE-57A9 supply it.

## Design / approach

1. **csproj.** `<Version>2.0.0</Version>`. Replace `<PackageReleaseNotes>` with a short prose summary
   mirroring the top of the new `RELEASENOTES.md` section and ending
   `See RELEASENOTES.md for the full details.` — it must lead with the breaking change, since that is
   what a consumer needs to see in the NuGet gallery. Extend `<Description>` and `<PackageTags>` to
   mention PQC key PEM support **and CRC checksums** (FEATURE-D254). Confirm in passing that the
   packable-library properties are all still
   present, `GeneratePackageOnBuild` is still off, and no symbol property (`IncludeSymbols`,
   `SymbolPackageFormat`, `PublishRepositoryUrl`, `EmbedUntrackedSources`) has crept in.

2. **`RELEASENOTES.md`.** Prepend `# Enigma.Core v2.0.0 Release Notes` above the 1.1.0 section, using
   the subsequent-release variant and only the non-empty sub-sections, in this order:

   - **Breaking Changes & Migration** — the headline. Consolidate from the two completion docs:
     - `IPublicKeyService`: the seven-row removed/replacement table; `GenerateRsaKeyPair` →
       `GenerateRsaKey`; the `char[]? password` parameter removed from `DecryptPkcs1`, `DecryptOaep`
       and `Sign` — the passphrase is now supplied once, at `RsaKey.ImportPrivateKeyPem`.
     - `IX509CertificateService`: the five migrated members; `ImportPkcs12` now returns
       `(string certificatePem, RsaKey privateKey)`; positional callers must re-check argument order
       where `char[]? password` was removed.
     - **Nothing was deprecated** — removed members are gone, not `[Obsolete]`. State this plainly so
       consumers know there is no transition window.
     - **Encrypted private-key PEM format changed** on *write*: from traditional-OpenSSL
       (`RSA PRIVATE KEY` + `Proc-Type`/`DEK-Info`, keyed by OpenSSL's legacy `EVP_BytesToKey` —
       MD5, single iteration) to **PBES2** (`ENCRYPTED PRIVATE KEY`, PBKDF2-HMAC-SHA256,
       AES-256-CBC, 16-byte salt, 600 000 iterations). **Reading still accepts all three forms** —
       unencrypted PKCS#8, traditional-OpenSSL, and PBES2 — so existing key files keep working. Note
       the one-time ~0.6 s cost of a 600 000-iteration derivation. **The format change is
       file-compatible in both directions:** 1.x also reads PBES2 (verified — its BouncyCastle-backed
       reader handles PBKDF2-HMAC-SHA256 / AES-256-CBC / 600 000 iterations, and the repo's own
       `pk_key1.pem` fixture is already a PBES2 file read by shipping 1.1.0 code). So only the *API*
       breaks, not the key files. **Do not** write a "keys written by 2.0.0 cannot be read by 1.x"
       warning — it is false.
     - Point at `docs/guides/public-key.md` and `docs/guides/certificates.md` for the worked
       migration examples.
   - **New Features** — ML-DSA and ML-KEM key PEM support: `IMLDsaPemService` / `IMLKemPemService`
     with their factories, public/private/encrypted PEM, parameter-set recovery from the algorithm
     OID, and the three private-key formats (`Seed` default, `ExpandedKey`, `SeedAndExpandedKey`) via
     `GenerateKeyPairPem`. `IMLDsaService` / `IMLKemService` are unchanged.

     Also the new **Checksum module** (FEATURE-D254): `Enigma.Core.Checksum` with `IChecksumService` /
     `IChecksumServiceFactory` and seven named CRC variants — CRC-16/ARC, CCITT-FALSE, XMODEM, MODBUS,
     KERMIT, CRC-32/ISO-HDLC and CRC-32C — sync and async, `byte[]` (big-endian) or `uint`. Say plainly
     that CRC is error detection, **not** a security primitive. Cross-check the surface against
     `docs/plan/FEATURE-D254.md`.
   - **Compatibility** — target frameworks unchanged; BouncyCastle floor unchanged at 2.7.0;
     ML-KEM/ML-DSA raw key, ciphertext and signature encodings unchanged, so material persisted by
     1.x keeps working; RSA key **files** keep working, RSA **code** does not; the Checksum module is
     purely additive and adds **no** new dependency.
   - **Version** — `2.0.0`.

   No *Fixes* section unless one of the three items actually produced a fix.

3. **README.** Update the line-11 callout to `> **What's new in 2.0** — …` leading with the breaking
   change and naming the PQC PEM and CRC-checksum additions in one clause. FEATURE-D254 added a
   **Checksums** bullet to the Features list — confirm it is present and still reads true. Keep the
   packed-README link rule (only
   `LICENSE.md` / `RELEASENOTES.md` linked; guides referenced in prose). Verify line 46's
   "Targets .NET Standard 2.0, .NET 8.0, and .NET 10.0; built on BouncyCastle 2.7.0" is still exact.

4. **`SECURITY.md`.** Supported-versions table `1.1.x` → `2.0.x`. Decide explicitly whether 1.1.x
   keeps a support row; record the decision in the completion doc either way.

5. **Guide index.** Re-read `docs/guides/README.md`: the public-key and PQC entries were rewritten by
   FEATURE-6852 / FEATURE-5413, so refresh their one-line descriptions if they no longer describe the
   guides. FEATURE-D254 added a **Checksums** entry under *Data & helpers* — confirm it is present and
   accurate.

6. **Snippet-verification gate.** Unlike 1.1.0, this release **does** change the guides, so verify
   every snippet in `docs/guides/public-key.md`, `certificates.md`, `pqc.md` and the new
   `checksum.md` compiles against the shipped API before packing.

7. **Pack-verify (run locally, then delete).**

   ```bash
   dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts-verify
   ```

   Inspect the artifact and its nuspec, then **delete `./artifacts-verify`** — it is never committed.

8. **Print the runbook** (never run it) — pre-flight build/test, merge to `main`, bare **`2.0.0`** tag,
   `dotnet pack` into `./artifacts`, `dotnet nuget push`, then the post-publish verification list. The
   API key is never echoed, stored or committed.

## Acceptance criteria

1. `src/Enigma.Core/Enigma.Core.csproj` carries `<Version>2.0.0</Version>` and a
   `<PackageReleaseNotes>` that leads with the breaking change and mirrors the new notes section;
   `<Description>` and `<PackageTags>` mention PQC key PEM support **and CRC checksums**.
2. `RELEASENOTES.md` has a top **2.0.0** section containing, at minimum, *Breaking Changes &
   Migration*, *New Features*, *Compatibility* and *Version*; the 1.1.0 and 1.0.0 sections are
   preserved below it unmodified. *New Features* covers **both** the PQC PEM services (FEATURE-5413)
   and the Checksum module (FEATURE-D254).
3. The *Breaking Changes & Migration* section lists **every** removed member of `IPublicKeyService`
   with its replacement, **every** changed member of `IX509CertificateService`, states that nothing
   was deprecated, and documents the encrypted-PEM write-format change together with the
   read-compatibility guarantee.
4. `README.md` (callout), `SECURITY.md` (supported versions) and `docs/guides/README.md` are
   consistent at **2.0.0**; `README.md`'s Features list and `docs/guides/README.md` both list the
   Checksum module; badges and the TFM list are unchanged; and `docs/RELEASE.md`'s
   tag-convention sentence reflects the actual tags (`1.0.0`, `1.1.0`) instead of claiming the repo
   has none.
5. Every snippet in the three rewritten guides **and in `docs/guides/checksum.md`** compiles against
   the shipped 2.0.0 API.
6. Release build clean with **zero warnings** across all three TFMs and the full suite green on
   net8.0 and net10.0 — re-verified in this phase.
7. **Pack-verify passes**: the `.nupkg` version is `2.0.0`; the verify directory contains the `.nupkg`
   and **nothing else** (no `.snupkg`); `README.md` is embedded and non-empty; `LICENSE.md` is
   embedded; the nuspec's `version`, `title`, `license type="file"`, `readme` and `releaseNotes` are
   correct; the dependency groups show **`BouncyCastle.Cryptography >= 2.7.0`** on all three TFMs and
   `System.Buffers` on `netstandard2.0` only. The verify directory is then deleted.
8. The tag / pack / push runbook is **printed, not run**, using the bare `2.0.0` tag format.
9. `docs/done/FEATURE-19C7.md` records the files changed, the pack-verify findings (including the
   observed per-TFM dependency floors), the SECURITY.md support-window decision, and states that
   tagging and publishing remain the maintainer's. It also carries the **snippet-verification
   coverage table** the `dotnet-release` skill requires — per file *snippets · symbols · mismatches ·
   uncertain*, with totals, for `docs/guides/public-key.md`, `certificates.md`, `pqc.md` and
   `checksum.md` — in the shape of `docs/done/FEATURE-28C7.md`.
10. The item's roadmap row flips to `DONE`.
