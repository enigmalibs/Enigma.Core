# Enigma.Core — Roadmap

Single registry of all tracked work items. Details live in `docs/plan/<ID>.md`; completion
records in `docs/done/<ID>.md`. Row order is the work order (append new items last).

| ID           | Title                                              | Status      | Plan                      |
|--------------|----------------------------------------------------|-------------|---------------------------|
| FEATURE-56AA | Repository & solution bootstrap                    | DONE        | docs/plan/FEATURE-56AA.md |
| FEATURE-4442 | Abstraction skeleton (interfaces + empty impls)    | IN PROGRESS | docs/plan/FEATURE-4442.md |
| - PHASE01    | Shared foundation (root types + shared enums)      | DONE        | (in FEATURE-4442.md)      |
| - PHASE02    | Symmetric (BlockCiphers, StreamCiphers) + Padding  | DONE        | (in FEATURE-4442.md)      |
| - PHASE03    | Hashing (Hash, Hmac) + KeyDerivation               | TODO        | (in FEATURE-4442.md)      |
| - PHASE04    | Otp + Encoding                                     | TODO        | (in FEATURE-4442.md)      |
| - PHASE05    | Asymmetric (PublicKey, Pqc)                        | TODO        | (in FEATURE-4442.md)      |
| - PHASE06    | Certificates (X.509)                               | TODO        | (in FEATURE-4442.md)      |
