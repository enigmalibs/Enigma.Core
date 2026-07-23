# FEATURE-4620 — PHASE02 — Per-category documentation & samples

**Status:** DONE
**Branch:** `feature/feature-4620-phase02-docs-samples` (cut from the PHASE01 commit `3aa8e6a`)

## Summary

Added the per-category documentation set for the v1.0.0 NuGet release: one markdown guide per
library category plus an index, all under `docs/guides/`. Each guide follows a consistent shape
— **supported algorithms/schemes → key types → copy-pasteable C# usage samples** — and every code
sample was written and then re-verified against the **actual public API** (service + factory + DI
pattern), not from memory. The 13 guides were drafted in parallel by sub-agents, each handed the
verified API surface and strict anti-hallucination rules; the owner then re-checked every snippet,
factory-construction pattern, enum, and method signature against source before sign-off.

This is a doc-only phase — no production code changed, so there was nothing to build or test. The
acceptance criteria are met by well-formedness and inspection against source (see *Build/test
evidence*).

## Files/modules touched

**Created (14 files under `docs/guides/`):**

- `README.md` — documentation index; categorized list linking every guide via **relative** URLs.
- `block-ciphers.md` — 12 engines (AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST5,
  IDEA, SEED, ARIA, SM4); ECB/CBC/CTR/GCM; GCM AAD + `GcmMacSize`; `PaddingScheme` integration.
- `stream-ciphers.md` — ChaCha20-RFC7539, ChaCha20, Salsa20 (per-cipher nonce sizes).
- `padding.md` — None, PKCS#7, ISO 7816-4, ISO 10126-2, ANSI X9.23; `IPaddingService` primitives
  vs the `PaddingScheme` enum passed to the block-cipher service.
- `hashing.md` — MD5, SHA-1, SHA-256, SHA-512, SHA-3 (selectable bit length); streaming +
  progress/cancellation.
- `hmac.md` — HMAC-SHA1/256/512; in-memory `ComputeHmac` and streaming `ComputeHmacAsync`.
- `key-derivation.md` — PBKDF2 (4 PRFs) and Argon2 (variants + versions); OWASP/RFC 9106 guidance.
- `encoding.md` — Base64, Base32 (RFC 4648), hex.
- `otp.md` — HOTP (RFC 4226), TOTP (RFC 6238), `otpauth://` provisioning; documents the injected
  factory chain (`HmacServiceFactory → HotpServiceFactory → TotpServiceFactory`, and
  `OtpProvisioningServiceFactory(EncodingServiceFactory)`).
- `public-key.md` — RSA keygen (PEM, optional encrypted private key), PKCS#1 v1.5 & OAEP
  encrypt/decrypt, sign/verify.
- `pqc.md` — ML-KEM 512/768/1024 (encapsulate/decapsulate), ML-DSA 44/65/87 (sign/verify;
  deterministic flag).
- `certificates.md` — self-signed generation, CSR + validation, issuance, chain validation,
  `IsRevoked`/CRL, PKCS#12 import/export, DER import/export, `GetCertificateInfo` (incl.
  Thumbprint).
- `extensions.md` — `EncodingExtensions` (`byte[]`/`string` helpers) and `StreamExtensions`
  (typed sync + async `Stream` read/write, incl. length-value / tag-length-value framing).
- `utils.md` — `RandomUtils.GenerateRandomBytes` and `CryptoDefaults.StreamBufferSize`.

**Modified:**

- `docs/roadmap.md` — PHASE02 status `TODO → IN PROGRESS → DONE`.
- `docs/plan/FEATURE-4620.md` — PHASE02 status `TODO → IN PROGRESS → DONE`.

**Deleted:** none.

## Deviations & follow-ups

- **No deviations from the plan.** All 13 guides + index were produced under `docs/guides/` with
  the prescribed shape and relative-link index; no absolute URLs; samples match the real public
  API.
- **Verification notes surfaced during the API audit (already reflected in the guides):**
  - Only three factories require constructor injection — `HotpServiceFactory(IHmacServiceFactory)`,
    `TotpServiceFactory(IHotpServiceFactory)`, `OtpProvisioningServiceFactory(IEncodingServiceFactory)`.
    All other `*ServiceFactory` types are parameterless. The OTP guide documents the composition
    chain explicitly.
  - There is deliberately **no** `AddEnigmaCore` DI-container helper (out of scope per the plan);
    guides construct factories with `new` and note the interfaces are DI-registration-friendly.
  - `EncodingExtensions`/`StreamExtensions` use C# 14 `extension(...)` member syntax; they are
    still consumed as ordinary extension methods. There is no sync `WriteByte`/`ReadByte`
    extension (those names collide with `Stream`'s own members) — only the async single-byte
    helpers exist; the extensions guide calls this out.
- **Line endings (CRLF):** no line-ending churn observed; the repo has a `.gitattributes`. No
  action taken (recommendation-only per the workflow).
- **Follow-up (not blocking):** PHASE03 will add the summary `README.md`, and its *Documentation*
  section should point to `docs/guides/` (prose-only, no per-sample links) — consistent with the
  index added here.

## Build/test evidence

- **Nothing to build or test** — this phase adds only markdown documentation; no production code,
  csproj, or tests changed. (Definition-of-Done criteria 1–2 satisfied by the doc-only equivalent.)
- **Well-formedness / inspection (criterion 3):**
  - All 13 guides + `docs/guides/README.md` exist and are well-formed markdown.
  - Every code sample was re-verified by the owner against the source public API — factory
    constructors, method signatures, enum members, and property names all match the interfaces
    and types under `src/Enigma.Core/`. Two runtime-behaviour prose claims (padding `blockSize`
    1–255 → `ArgumentException`; `NoPaddingService` ignoring `blockSize`) were confirmed against
    `PaddingService.cs` / `NoPaddingService.cs`.
  - Index links checked: all 13 relative links resolve to existing files; no absolute URLs and no
    nuget-breaking links anywhere in `docs/guides/`.
- **Roadmap + plan statuses updated (criterion 4);** this completion doc written (criterion 5).
