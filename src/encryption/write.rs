//! Stub for PQ-File-Crypt header writing.
//!
//! TODO: Replace with real header writing using PQ ciphertext types.
//! For placeholder, uses simplified format without PQ elements.

use crate::aliases::*;
use std::collections::HashMap;
use std::io::{self, Write};

// Stub Ciphertext (matches crypto::xwing_kem)
pub struct Ciphertext; // Placeholder; full impl will use real X-Wing CT

impl Ciphertext {
    pub fn to_bytes(&self) -> [u8; 1600] {
        unimplemented!("PQ ciphertext to bytes not implemented");
    }
}

/// Stub parameters for header (simplified).
pub struct HeaderParams<'a> {
    pub key_type: u8,
    pub salt: Option<&'a Salt16>,
    pub iterations: Option<u32>,
    pub memory_kib: Option<u32>,
    pub parallelism: Option<u32>,
    pub extensions: &'a HashMap<u8, Vec<u8>>,
    pub ct: &'a Ciphertext, // Stub
    pub nonce: &'a GcmNonce12,
}

/// Stub write header.
///
/// TODO: Write full PQ header with extensions and PQ CT.
/// For now, writes basic magic + version.
pub fn write_header<W: Write>(mut _writer: W, _params: HeaderParams) -> io::Result<()> {
    unimplemented!("Header writing not implemented in placeholder");
}
