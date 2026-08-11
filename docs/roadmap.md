# Enigma.Core — Roadmap

Single registry of all tracked work items. Details live in `docs/plan/<ID>.md`; completion
records in `docs/done/<ID>.md`. Row order is the work order (append new items last).

| ID           | Title                                                                         | Status | Plan                      |
|--------------|-------------------------------------------------------------------------------|--------|---------------------------|
| FEATURE-56AA | Repository & solution bootstrap                                               | DONE   | docs/plan/FEATURE-56AA.md |
| FEATURE-4442 | Abstraction skeleton (interfaces + empty impls)                               | DONE   | docs/plan/FEATURE-4442.md |
| - PHASE01    | Shared foundation (root types + shared enums)                                 | DONE   | (in FEATURE-4442.md)      |
| - PHASE02    | Symmetric (BlockCiphers, StreamCiphers) + Padding                             | DONE   | (in FEATURE-4442.md)      |
| - PHASE03    | Hashing (Hash, Hmac) + KeyDerivation                                          | DONE   | (in FEATURE-4442.md)      |
| - PHASE04    | Otp + Encoding                                                                | DONE   | (in FEATURE-4442.md)      |
| - PHASE05    | Asymmetric (PublicKey, Pqc)                                                   | DONE   | (in FEATURE-4442.md)      |
| - PHASE06    | Certificates (X.509)                                                          | DONE   | (in FEATURE-4442.md)      |
| FEATURE-61D1 | Implementation foundation (packages, test harness, shared Extensions/Utils)   | DONE   | docs/plan/FEATURE-61D1.md |
| FEATURE-0399 | Encoding implementation (Base64, Hex, Base32)                                 | DONE   | docs/plan/FEATURE-0399.md |
| FEATURE-26A5 | Hashing implementation (Hash + HMAC)                                          | DONE   | docs/plan/FEATURE-26A5.md |
| FEATURE-679F | KeyDerivation implementation (PBKDF2 + Argon2)                                | DONE   | docs/plan/FEATURE-679F.md |
| FEATURE-5761 | OTP implementation (HOTP, TOTP, provisioning)                                 | DONE   | docs/plan/FEATURE-5761.md |
| - PHASE01    | HOTP/TOTP services + factories (full RFC parity)                              | DONE   | (in FEATURE-5761.md)      |
| - PHASE02    | Provisioning (un-defer OtpProvisioning + OtpAuthParameters as DI service)     | DONE   | (in FEATURE-5761.md)      |
| FEATURE-534F | Symmetric implementation (Block + Stream ciphers) + Padding                   | DONE   | docs/plan/FEATURE-534F.md |
| - PHASE01    | Padding                                                                       | DONE   | (in FEATURE-534F.md)      |
| - PHASE02    | BlockCiphers (12 algorithms, 4 modes incl. GCM + AAD)                         | DONE   | (in FEATURE-534F.md)      |
| - PHASE03    | StreamCiphers                                                                 | DONE   | (in FEATURE-534F.md)      |
| FEATURE-2E3E | Asymmetric.PublicKey implementation (RSA)                                     | DONE   | docs/plan/FEATURE-2E3E.md |
| FEATURE-0D6D | Asymmetric.Pqc implementation (ML-DSA, ML-KEM)                                | DONE   | docs/plan/FEATURE-0D6D.md |
| FEATURE-099B | Certificates implementation (X.509)                                           | DONE   | docs/plan/FEATURE-099B.md |
| - PHASE01    | Generation, CSR & issuance (+ restored extension controls & CSR verification) | DONE   | (in FEATURE-099B.md)      |
| - PHASE02    | Chain validation & CRL revocation                                             | DONE   | (in FEATURE-099B.md)      |
| - PHASE03    | CertificateInfo parsing, PFX & DER (restored)                                 | DONE   | (in FEATURE-099B.md)      |
| FEATURE-4620 | NuGet release preparation (v1.0.0)                                            | DONE   | docs/plan/FEATURE-4620.md |
| - PHASE01    | Package metadata & build config + license check                               | DONE   | (in FEATURE-4620.md)      |
| - PHASE02    | Per-category documentation & samples                                          | DONE   | (in FEATURE-4620.md)      |
| - PHASE03    | Summary README + release notes + community files                              | DONE   | (in FEATURE-4620.md)      |
| - PHASE04    | Release runbook & final cut prep                                              | DONE   | (in FEATURE-4620.md)      |
| FEATURE-28C7 | Release-doc polish: drop Downloads badge & verify guide/README samples        | DONE   | docs/plan/FEATURE-28C7.md |
| FEATURE-797D | BouncyCastle 2.7.0 upgrade & v1.1.0 release                                   | DONE   | docs/plan/FEATURE-797D.md |
| - PHASE01    | Upgrade to BouncyCastle 2.7.0                                                 | DONE   | (in FEATURE-797D.md)      |
| - PHASE02    | Release v1.1.0                                                                | DONE   | (in FEATURE-797D.md)      |
| FEATURE-5413 | PQC PEM services (ML-DSA / ML-KEM)                                            | DONE   | docs/plan/FEATURE-5413.md |
| - PHASE01    | Shared PEM internals + ML-DSA PEM service                                     | DONE   | (in FEATURE-5413.md)      |
| - PHASE02    | ML-KEM PEM service                                                            | DONE   | (in FEATURE-5413.md)      |
| FEATURE-6852 | RsaKey handle for the PublicKey module (BREAKING)                             | DONE   | docs/plan/FEATURE-6852.md |
| - PHASE01    | RsaKey + PBES2 write / three-format read (additive)                           | DONE   | (in FEATURE-6852.md)      |
| - PHASE02    | Cut the PEM-string surface (BREAKING)                                         | DONE   | (in FEATURE-6852.md)      |
| FEATURE-57A9 | Certificates on the RsaKey handle (BREAKING)                                  | DONE   | docs/plan/FEATURE-57A9.md |
| FEATURE-D254 | Checksum module (CRC-16 & CRC-32)                                             | DONE   | docs/plan/FEATURE-D254.md |
| FEATURE-19C7 | Release v2.0.0                                                                | DONE   | docs/plan/FEATURE-19C7.md |
