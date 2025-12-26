use crate::aliases::*;
use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHasher, SaltString};
use rand_core::RngCore;
use std::collections::HashMap;
use std::io::{self as Io, Result as IoResult};

// Constants (from ROADMAP and spec)
pub const MAGIC: &[u8; 6] = b"PQ-AES";
pub const VERSION: u8 = 0x01;

pub const KEY_TYPE_RANDOM: u8 = 0x00;
pub const KEY_TYPE_PASSWORD: u8 = 0x01;

pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const XWING_CT_SIZE: usize = 1600; // X-Wing-1024 ciphertext size (1568 ML-KEM + 32 X25519)

pub const FIXED_HEADER_SIZE: usize = MAGIC.len() + 1 + 1; // magic + version + key_type
pub const EXTENSIONS_LEN_SIZE: usize = 2; // u16 for extensions length

// Dual-Mode Key Derivation
#[derive(Clone, Debug)]
pub enum KeyInput {
    Random(RootSeed32),
    Password {
        password: PasswordString,
        salt: Option<Salt16>,
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    },
}

impl KeyInput {
    pub fn key_type(&self) -> u8 {
        match self {
            KeyInput::Random(_) => KEY_TYPE_RANDOM,
            KeyInput::Password { .. } => KEY_TYPE_PASSWORD,
        }
    }
}

pub fn derive_root_seed(
    input: KeyInput,
    rng: Option<&mut dyn RngCore>,
) -> IoResult<(RootSeed32, Option<Salt16>)> {
    match input {
        KeyInput::Random(seed) => Ok((seed, None)),
        KeyInput::Password {
            password,
            salt,
            iterations,
            memory_kib,
            parallelism,
        } => {
            let salt = salt.unwrap_or_else(|| {
                if let Some(r) = rng {
                    let mut bytes = [0u8; 16];
                    r.fill_bytes(&mut bytes);
                    Salt16::new(bytes)
                } else {
                    panic!("RNG required for automatic salt generation (enable 'rand' feature or pass a custom RNG)");
                }
            });
            let salt_bytes = salt.expose_secret();

            let salt_str = SaltString::encode_b64(salt_bytes)
                .map_err(|_| Io::Error::new(Io::ErrorKind::InvalidInput, "Salt encoding failed"))?;

            let params =
                Params::new(memory_kib, iterations, parallelism, Some(32)).map_err(|_| {
                    Io::Error::new(Io::ErrorKind::InvalidInput, "Invalid Argon2 params")
                })?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let pw_bytes = password.expose_secret().as_bytes();
            let hash = argon2
                .hash_password(pw_bytes, &salt_str)
                .map_err(|_| Io::Error::new(Io::ErrorKind::InvalidInput, "Argon2 failed"))?;

            let mut seed_bytes = [0u8; 32];
            seed_bytes.copy_from_slice(&hash.hash.unwrap().as_bytes()[0..32]);
            let root_seed = RootSeed32::new(seed_bytes);
            Ok((root_seed, Some(salt)))
        }
    }
}

// Extensions Helpers
pub fn serialize_extensions(extensions: &HashMap<u8, Vec<u8>>) -> Vec<u8> {
    let mut data = Vec::new();
    for (tag, value) in extensions {
        data.push(*tag);
        data.extend_from_slice(&(value.len() as u16).to_be_bytes());
        data.extend_from_slice(value);
    }
    data
}

pub fn parse_extensions(data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut extensions = HashMap::new();
    let mut pos = 0;
    while pos + 3 <= data.len() {
        let tag = data[pos];
        pos += 1;
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len <= data.len() {
            extensions.insert(tag, data[pos..pos + len].to_vec());
            pos += len;
        } else {
            break;
        }
    }
    extensions
}
