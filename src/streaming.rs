//! PQ-AES Streaming AES-GCM Module
//!
//! Moved from common.rs for modularity. Handles incremental GCM encrypt/decrypt with CTR and GHASH.

use crate::aliases::*;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit};
use generic_array::GenericArray;
use ghash::{GHash, universal_hash::UniversalHash};
use std::io::ErrorKind;
use std::io::{self as Io, Result as IoResult};
use typenum::consts::U16;

type Block = GenericArray<u8, U16>;

/// Streaming AES-256-GCM for constant-memory encryption/decryption of large files.
/// Processes data in chunks, computes GHASH incrementally, and verifies/authenticates at the end.
pub struct StreamingAesGcm {
    cipher: Aes256,
    ghash: GHash,
    y0: Block,    // For tag XOR (computed from nonce)
    counter: u32, // CTR counter starting from 2 (Y1, then Y2...)
    aad_len: u64,
    data_len: u64,
    finalized: bool,
}

impl StreamingAesGcm {
    /// Initialize with AES key, nonce, and optional AAD.
    pub fn new(key: &AesKey32, nonce: &GcmNonce12, aad: &[u8]) -> Self {
        let key_bytes = key.expose_secret();
        let nonce_bytes = nonce.expose_secret();

        let cipher = Aes256::new(GenericArray::from_slice(key_bytes));
        let mut zero_block = Block::default();
        cipher.encrypt_block(&mut zero_block); // H = E(K, 0^128)
        let h = zero_block;
        let mut ghash = GHash::new(&h);

        // Y0 = nonce || 0x00000001
        let mut y0 = Block::default();
        y0[0..12].copy_from_slice(nonce_bytes);
        y0[15] = 1;
        let mut y0_mut = y0;
        cipher.encrypt_block(&mut y0_mut); // H = E(K, 0^128)
        let enc_y0 = y0_mut;

        // Update GHASH with AAD (padded)
        let mut aad_padded = aad.to_vec();
        while !aad_padded.len().is_multiple_of(16) {
            aad_padded.push(0);
        }
        ghash.update_padded(&aad_padded);

        Self {
            cipher,
            ghash,
            y0: enc_y0,
            counter: 2, // Y1 = nonce || 1 (implicit), Y2 = nonce || 2 for first block
            aad_len: aad.len() as u64,
            data_len: 0,
            finalized: false,
        }
    }

    /// Encrypt plaintext chunk, return ciphertext.
    /// Call repeatedly, then finalize_encrypt.
    pub fn update_encrypt(&mut self, plaintext: &[u8]) -> IoResult<Vec<u8>> {
        if self.finalized {
            return Err(Io::Error::new(ErrorKind::InvalidInput, "Already finalized"));
        }
        self.update(plaintext, true)
    }

    /// Decrypt ciphertext chunk, return plaintext.
    /// Call repeatedly, then finalize_decrypt.
    pub fn update_decrypt(&mut self, ciphertext: &[u8]) -> IoResult<Vec<u8>> {
        if self.finalized {
            return Err(Io::Error::new(ErrorKind::InvalidInput, "Already finalized"));
        }
        self.update(ciphertext, false)
    }

    /// Shared update for encrypt/decrypt.
    fn update(&mut self, input: &[u8], encrypt: bool) -> IoResult<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len());
        let mut remaining = input;

        while !remaining.is_empty() {
            let mut block = Block::default();
            let len = remaining.len().min(16);

            block[..len].copy_from_slice(&remaining[..len]);
            let block_out = self.process_block(&block, encrypt);
            output.extend_from_slice(&block_out[..len]);

            self.data_len += len as u64;
            remaining = &remaining[len..];
        }

        Ok(output)
    }

    /// Process one block: CTR encrypt/decrypt + GHASH update.
    fn process_block(&mut self, block: &Block, encrypt: bool) -> Block {
        // Generate keystream: E(K, Y_i)
        let mut y_i = Block::default();
        y_i[0..12].copy_from_slice(&self.y0[0..12]); // nonce part
        y_i[12..].copy_from_slice(&self.counter.to_be_bytes()[..4]);
        self.counter += 1;

        let mut y_i_mut = y_i;
        self.cipher.encrypt_block(&mut y_i_mut);
        let keystream = y_i_mut;

        // XOR with block
        let mut output = *block;
        for (o, k) in output.iter_mut().zip(keystream.iter()) {
            *o ^= *k;
        }

        // GHASH update with ciphertext/plaintext depending on encrypt/decrypt
        // For GCM, GHASH input is ciphertext in both cases
        let ghash_input = if encrypt { &output } else { block };
        self.ghash.update_padded(ghash_input.as_slice());

        output
    }

    /// Finalize encryption, return GCM tag.
    pub fn finalize_encrypt(mut self) -> IoResult<GcmTag16> {
        if self.finalized {
            return Err(Io::Error::new(ErrorKind::InvalidInput, "Already finalized"));
        }
        self.finalized = true;

        // Pad and finalize GHASH
        let mut len_block = Block::default();
        len_block[0..8].copy_from_slice(&(self.aad_len * 8).to_be_bytes());
        len_block[8..16].copy_from_slice(&(self.data_len * 8).to_be_bytes());
        self.ghash.update(&[len_block]);

        let ghash_out = self.ghash.finalize();
        let mut tag = [0u8; 16];
        for (t, (g, y)) in tag
            .iter_mut()
            .zip(ghash_out.as_slice().iter().zip(self.y0.iter()))
        {
            *t = *g ^ *y;
        }
        Ok(GcmTag16::new(tag))
    }

    /// Finalize decryption, verify tag.
    pub fn finalize_decrypt(mut self, tag: &GcmTag16) -> IoResult<()> {
        if self.finalized {
            return Err(Io::Error::new(ErrorKind::InvalidInput, "Already finalized"));
        }
        self.finalized = true;

        let expected_tag = self.finalize_encrypt()?;
        if expected_tag.expose_secret() != tag.expose_secret() {
            return Err(Io::Error::new(
                ErrorKind::InvalidData,
                "GCM tag verification failed",
            ));
        }
        Ok(())
    }
}
