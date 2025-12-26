# PQ-File-Crypt

A **placeholder** crate for post-quantum secure file encryption in Rust. This reserves the `pq-file-crypt` name on crates.io while the full, audited implementation is under private development. The eventual crate will provide streaming, authenticated file encryption using hybrid post-quantum cryptography (e.g., ML-KEM-1024 + X25519 for key wrapping, AES-256-GCM for payload).

## Features (Intended)
- Password-based key derivation (Argon2id) with salts.
- Hybrid PQ key encapsulation to resist quantum attacks.
- Streaming AES-256-GCM for constant-memory encryption of large files.
- Extensible file format with metadata (magic `PQ-AES`, extensions).
- Dual-mode keys: random or password-derived.
- Support for AEAD and verification.

Currently, only safe components (key derivation, streaming GCM, aliases) are implemented. PQ elements are stubbed—do **not** use for production.

## Installation

```bash
git clone https://github.com/Slurp9187/pq-file-crypt
cd pq-file-crypt
cargo build
```

## Usage Example

```rust
use pq_file_crypt::{encrypt, KeyInput};
use std::fs::File;
use rand::thread_rng;

// Placeholder: Actual PQ encryption stubs not yet implemented
let key_input = KeyInput::Random(/* seed */);
encrypt(input, output, key_input, &mut rng).unwrap(); // Will panic until stubs are filled
```

## Security Disclaimer

This placeholder includes no live PQ crypto—it's for name reservation and proof of intent. The real implementation (e.g., using `libcrux` for ML-KEM) is in a private repo awaiting internal audit for faithful implementation of official NIST/PQ specifications and ensuring no security issues. **Avoid using this for anything sensitive**. For now, rely on crates like `aes-gcm` directly.

## Roadmap
- [x] Implement streaming AES-256-GCM.
- [x] Add key derivation and format headers.
- [ ] Integrate internally audited PQ primitives.
- [ ] Internal audit for faithful spec implementation and security review, then v1.0 release.

Contributions welcome post-audit. See private dev notes for spec.

License: MIT/Apache-2.0.
