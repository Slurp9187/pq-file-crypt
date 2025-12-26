//! Placeholder Aliases for Secure Types
//!
//! Simple structs for fixed-size secrets. In full impl, use zeroize-on-drop.
//!
//! TODO: Replace with secure-gate or secrecy crate post-audit.

// Semantic types for AES-GCM
#[derive(Clone, Copy, Debug)]
pub struct AesKey32([u8; 32]);

impl AesKey32 {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GcmNonce12([u8; 12]);

impl GcmNonce12 {
    pub fn new(nonce: [u8; 12]) -> Self {
        Self(nonce)
    }
    pub fn expose_secret(&self) -> &[u8; 12] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GcmTag16([u8; 16]);

impl GcmTag16 {
    pub fn new(tag: [u8; 16]) -> Self {
        Self(tag)
    }
    pub fn expose_secret(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RootSeed32([u8; 32]);

impl RootSeed32 {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Salt16([u8; 16]);

impl Salt16 {
    pub fn new(salt: [u8; 16]) -> Self {
        Self(salt)
    }
    pub fn expose_secret(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct XwingCt1600([u8; 1600]);

impl XwingCt1600 {
    pub fn new(ct: [u8; 1600]) -> Self {
        Self(ct)
    }
    pub fn expose_secret(&self) -> &[u8; 1600] {
        &self.0
    }
}

// Dynamic password
#[derive(Clone, Debug)]
pub struct PasswordString(String);

impl PasswordString {
    pub fn new(pw: String) -> Self {
        Self(pw)
    }
    pub fn expose_secret(&self) -> &String {
        &self.0
    }
}
