# PQ-File-Crypt v1.0 Prototype Format Specification

**Date**: December 24, 2025  
**Version**: 1.0 (Prototype)  
**Status**: Draft (Pre-Internal Audit)

*Disclaimer*: This is a high-level prototype specification for the PQ-File-Crypt file format, outlining the intended structure for post-quantum secure, streaming encryption. It is provided for documentation purposes in this placeholder crate. The full implementation will faithfully adhere to this spec after internal review for security and compliance with official standards (e.g., NIST PQ primitives). Do not implement or rely on this for production use until the audited v1.0 release. Sensitive details (e.g., algorithm implementations) remain private.

The encrypted file is a concatenation of three sections:

```
[Plaintext Header] || [Payload Ciphertext (e.g., AES-256-GCM or ChaCha20-Poly1305)] || [Authentication Tag (16 bytes)]
```

No delimiters or length prefixes beyond the header. The tag is always the last 16 bytes (seek to EOF - 16). The header is dynamic: fields vary based on Key Type (random/no KDF vs. password/KDF) and extensions (e.g., cipher protocol).

## 1. Plaintext Header (Variable Length)

Fully plaintext, parsed sequentially (big-endian multi-byte ints). Ends with a MAC for integrity. The structure is dynamic:
- **Key Type** determines if KDF fields are present (no KDF for CSRNG-random keys).
- **Extensions** allow specifying payload encryption protocol (e.g., AES-GCM vs. ChaCha20-Poly1305), with defaults if absent.

```
Bytes 0–7          : Magic                     = "PQ-CRYPT" (0x50 0x51 0x2D 0x43 0x52 0x59 0x50 0x54)  // Generic magic for multi-cipher support
Byte  8            : Version                   = 0x01 (v1.0 prototype)
Byte  9            : Key Type                  = 0x00 (Random/CSRNG, no KDF) or 0x01 (Password, requires KDF)
                     (If 0x00: Skip KDF fields; directly use CSRNG-derived seed for PQ keypair gen)
                     (If 0x01: Follow with KDF Type + params)
Byte  10           : KDF Type                  (only if Key Type = 0x01)
                     0x00 = Argon2id (default)
                     0x01 = PBKDF2-HMAC-SHA256 (future extension)
Bytes 11–26        : Salt                      (16 bytes, only if Key Type = 0x01)
Bytes 27–30        : Iterations                (u32 BE, only if Key Type = 0x01)
Bytes 31–34        : Memory KiB                (u32 BE, only if KDF Type = Argon2id and Key Type = 0x01; must be 0 for PBKDF2)
Bytes 35–38        : Parallelism               (u32 BE, only if KDF Type = Argon2id and Key Type = 0x01; must be 0 for PBKDF2)
Bytes N–N+1        : Extensions Length         (u16 BE; N = 10 if Key Type=0x00; N=10 + KDF fields if 0x01)
Bytes N+2 ...      : Extensions Data           (variable; TLV: Tag u8 + Length u16 BE + Value; skip unknowns)
                     Tags 0x00–0x0F: Standard
                       - 0x01 = Cipher Protocol (1 byte value):
                         0x00 = AES-256-GCM (default)
                         0x01 = ChaCha20-Poly1305
                       - 0x02 = KDF Flag (1 byte value, for explicit no-KDF confirmation):
                         0x00 = No KDF (CSRNG direct; redundant with Key Type=0x00, but extensible)
                         (Future: 0x02 = Scrypt, etc.)
Bytes ...          : PQ Hybrid Ciphertext      (fixed 1600 bytes, e.g., X-Wing KEM CT; derived from seed or KDF output)
Bytes ...          : Nonce                     (12 bytes, random; GCM nonce or ChaCha equiv.)
Bytes ...          : Header MAC                (32 bytes)
                     SHA3-256(HKDF-derived from PQ shared secret) over header bytes 0 to (but not incl.) this field
                     Info: "pq-file-crypt v1 header mac"
```

### Dynamic Header Layout Notes
- **No KDF (Key Type = 0x00)**: CSRNG-derived seed directly expands to PQ keypair (no salt/params). Header jumps from Byte 9 to Extensions Length (Byte 10–11). This "3rd mode" skips KDF entirely for efficiency in random-key scenarios.
- **With KDF (Key Type = 0x01)**: Includes KDF Type + conditional params (e.g., Argon2id needs memory/parallelism; PBKDF2 skips them, sets to 0).
- **Cipher Flexibility**: Default AES-GCM if no extension 0x01; explicitly set via TLV for ChaCha or future ciphers. Nonce size/format adjusts per cipher (fixed 12 bytes here).
- **Extensibility**: TLV allows future KDFs (e.g., tag 0x02) or no-KDF flags without changing core layout. Unknown tags skipped for forward compatibility.

### Header Size Examples (No Extensions)
- **Random/CSRNG (No KDF)**: 8 + 1 + 1 + 2 + 1600 + 12 + 32 = **1656 bytes** (skips Bytes 10–38).
- **Password + Argon2id (Full KDF)**: 8 + 1 + 1 + 1 + 16 + 4 + 4 + 4 + 2 + 1600 + 12 + 32 = **1685 bytes**.
- **Password + PBKDF2 (Minimal KDF)**: 8 + 1 + 1 + 1 + 16 + 4 + 2 + 1600 + 12 + 32 = **1677 bytes** (memory/parallelism = 0, skipped).

### Parsing Pseudocode
```rust
// Simplified Rust-like pseudocode for dynamic header parsing
fn parse_header(reader: &mut impl Read) -> Result<Header, Error> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    if &buf != b"PQ-CRYPT" { return Err(Error::InvalidMagic); }

    let version = reader.read_u8()?; if version != 0x01 { return Err(Error::UnsupportedVersion); }
    let key_type = reader.read_u8()?;

    let mut kdf_type = None; let mut salt = None; let mut iterations = 0u32;
    let mut memory_kib = 0u32; let mut parallelism = 0u32;
    if key_type == 1 {  // Password mode: Require KDF
        kdf_type = Some(reader.read_u8()?);
        salt = Some(read_fixed_bytes::<16>(reader)?);
        iterations = reader.read_u32()?;
        if kdf_type == Some(0x00) {  // Argon2id: Include params
            memory_kib = reader.read_u32()?;
            parallelism = reader.read_u32()?;
        } else {  // PBKDF2: Params must be 0
            let _zero_mem = reader.read_u32()?;  // Enforced =0
            let _zero_para = reader.read_u32()?; // Enforced =0
        }
    }  // Random mode: No KDF fields read

    let ext_len = reader.read_u16()?;
    let extensions = parse_tlv_extensions(reader, ext_len)?;  // e.g., get cipher from tag 0x01
    let cipher_mode = extensions.get(0x01).unwrap_or(&0x00);  // Default AES-GCM

    let pq_ct = read_fixed_bytes::<1600>(reader)?;  // PQ KEM CT
    let nonce = read_fixed_bytes::<12>(reader)?;  // Adjust format per cipher if needed

    let mac = read_fixed_bytes::<32>(reader)?;
    verify_header_mac(&header_bytes_so_far, &mac, &pq_derived_key)?;  // Early integrity

    Ok(Header {
        key_type, salt, kdf_type, iterations, memory_kib, parallelism,
        extensions, pq_ct, nonce, cipher_mode: *cipher_mode,
    })
}
```

## 2. Payload Ciphertext (Variable Length ≥ 0)

Follows header directly. Protocol determined by extension 0x01 (default AES-256-GCM).

- **Key**: 32-byte shared secret from PQ decapsulation (e.g., X-Wing KEM; derived from CSRNG seed or KDF output).
- **Nonce**: 12-byte from header (random, unique per file).
- **AAD**: Entire header (incl. MAC) for binding.
- **Streaming**: Chunked (e.g., 64 KiB); optional padding (PKCS#7 for AES).
- **Ciphers Supported**:
  - **AES-256-GCM**: Default; tag=0x00.
  - **ChaCha20-Poly1305**: tag=0x01; same nonce/tag sizes.
  - Future: Via extensions (e.g., tag=0x01=0x02 for XChaCha20).
- **Empty Payload**: 0 bytes allowed (e.g., encrypted empty file).

## 3. Authentication Tag (Fixed 16 Bytes)

Last 16 bytes of file.

- Authenticates: Ciphertext + header as AAD.
- **Type**: GCM tag (AES) or Poly1305 (ChaCha); size fixed at 16 bytes.
- **Location**: EOF - 16; reject if file size < header + 16.
- **Verification**: Fails if mismatch → "auth failure" (wrong password/corruption).

## Security Features
- **Version Binding (Anti-Downgrade Protection)**: Appends the version byte (e.g., 0x01 for v1.0) to the shared secret before PQ encapsulation (e.g., X-Wing KEM), embedding it within the PQ ciphertext. Post-decapsulation, extracts and verifies the byte against the header's Version field to prevent downgrade attacks and ensure version-matched decryption.
- **Header MAC**: Early integrity check (pre-decap) using HKDF from PQ shared secret.
- **PQ Protection**: All keys/CTs wrapped in hybrid PQ KEM (e.g., ML-KEM + X25519) for quantum resistance.
- **Dynamic/No-KDF Support**: Efficient for CSRNG scenarios (Key Type=0x00 skips KDF fields entirely).
- **Extensibility**: TLV for ciphers/KDFs/MFA without breaking older parsers (skip unknowns).
- **Compliance**: Faithful to NIST PQ standards (ML-KEM, etc.); internal audit ensures no issues.

## Implementation Notes
- **Rejection Rules**: Unknown Key Type/KDF Type/cipher → reject immediately. Missing required fields (e.g., salt for password) → invalid. MAC/tag mismatch → auth failure.
- **No KDF Handling**: For Key Type=0x00, use direct CSRNG seed for PQ derivation; extensions can confirm (tag 0x02=0x00).
- **Future Versions**: v0x02+ may add composite sigs, more KDFs (e.g., Scrypt via extension), or variable nonce sizes.
- **Audit Status**: This spec will guide the internal review for faithful, secure implementation.

For visuals, see [flowchart](pqfc_flowchart.md). Questions? See README.

