//! Stub for PQ-File-Crypt decryption.
//!
//! TODO: Implement full streaming decryption with PQ key decapsulation and GCM verification.
//! For placeholder: Unimplemented to avoid exposing pre-audit PQ code.

use crate::common::KeyInput;
use std::io::{self, Read, Write};

/// Stub decrypt function.
///
/// TODO: Read header, derive key, decapsulate AES key, stream decrypt with auth.
pub fn decrypt<R: Read, W: Write>(_input: R, _output: W, _key_input: KeyInput) -> io::Result<()> {
    unimplemented!("PQ decryption not implemented in placeholder—pending internal audit");
}
