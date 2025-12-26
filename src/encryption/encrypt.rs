//! Stub for PQ-File-Crypt encryption.
//!
//! TODO: Implement full streaming encryption with PQ key wrapping.
//! Currently unimplemented to avoid exposing sensitive pre-audit code.

use crate::common::KeyInput;
use rand_core::{CryptoRng, RngCore};
use std::io::{self, Read, Write};

/// Stub encrypt function.
///
/// TODO: Derive seed, generate PQ keys, self-encapsulate AES key, write header, stream encrypt.
/// For placeholder: Panics with unimplemented.
pub fn encrypt<R: Read, W: Write, RNG: RngCore + CryptoRng>(
    _input: R,
    _output: W,
    _key_input: KeyInput,
    _rng: &mut RNG,
) -> io::Result<()> {
    unimplemented!("PQ encryption not implemented in placeholder—pending internal audit");
}
