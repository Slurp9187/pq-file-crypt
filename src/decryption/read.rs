//! Stub for PQ-File-Crypt header reading.
//!
//! TODO: Implement full header parsing with PQ ciphertext validation.
//! For placeholder: Unimplemented.

use crate::aliases::*;
use std::io::{self, Read};

// Stub Ciphertext to match write.rs
pub struct Ciphertext;

impl Ciphertext {
    pub fn from_components(_ct_m: [u8; 1568], _ct_x: [u8; 32]) -> Self {
        unimplemented!("PQ Ciphertext from bytes not implemented");
    }
}

/// Stub for PQ-File-Crypt header reading (dynamic for AES/Chacha, no-KDF).
///
/// TODO: Parse "PQ-CRYPT" magic, conditional KDF fields, extensions for cipher, PQ CT, nonce.
/// For placeholder: Unimplemented.
pub fn read_header<R: Read>(
    _reader: R,
) -> io::Result<(u8, Option<Salt16>, Ciphertext, GcmNonce12)> {
    unimplemented!("Header reading not implemented in placeholder—pending internal audit");
}
