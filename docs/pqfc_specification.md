# PQ-File-Crypt v1.0 – Complete Concatenated File Format Specification

**Date**: December 24, 2025  
**Version**: 0x01  
**Status**: Final

The complete encrypted file is the concatenation of three sections in this order:

```
[Plaintext Header] || [AES-256-GCM Ciphertext] || [GCM Authentication Tag (16 bytes)]
```

No delimiters or length prefixes are needed beyond those in the header itself. The GCM tag is always the last 16 bytes of the file, allowing easy location by seeking to EOF - 16.

## 1. Plaintext Header (Variable Length)

The header is fully plaintext and parsed sequentially. All multi-byte integers are big-endian. The header ends with a MAC for integrity.

```
Bytes 0–5          : Magic                     = "PQ-AES" (0x50 0x51 0x2D 0x41 0x45 0x53)
Byte  6            : Version                   = 0x01
Byte  7            : Key Type                  = 0x00 (Random) or 0x01 (Password)
Byte  8            : KDF Type                  (only if Key Type = 0x01)
                     0x00 = Argon2id (default)
                     0x01 = PBKDF2-HMAC-SHA256
Bytes 9–24         : Salt                      (16 bytes, only if Key Type = 0x01)
Bytes 25–28        : Iterations                (u32 BE, only if Key Type = 0x01)
Bytes 29–32        : Memory KiB                (u32 BE, only if KDF Type = Argon2id; ignored/must be 0 for PBKDF2)
Bytes 33–36        : Parallelism               (u32 BE, only if KDF Type = Argon2id; ignored/must be 0 for PBKDF2)
Bytes N–N+1        : Extensions Length         (u16 BE)
Bytes N+2 ...     : Extensions Data           (variable; TLV: Tag u8 + Length u16 BE + Value)
                     Tags 0x00–0x0F reserved for standard use
Bytes ...         : X-Wing Ciphertext         (exactly 1600 bytes)
Bytes ...         : GCM Nonce                 (exactly 12 bytes random)
Bytes ...         : Header MAC                (exactly 32 bytes)
                     SHA3-256 over all header bytes from offset 0 up to (but not including) this field
                     Keyed via HKDF-SHA3-256 from decapsulated shared secret
                     (info = "pq-file-crypt v1 header mac")
```

### Header Size Examples (no extensions)
- **Random mode**: 6 + 1 + 1 + 2 + 1600 + 12 + 32 = **1654 bytes**
- **Password + Argon2id**: +1 +16 +12 = **1683 bytes**
- **Password + PBKDF2**: +1 +16 +4 = **1675 bytes**

## 2. AES-256-GCM Ciphertext (Variable Length ≥ 0)

Immediately follows the header (no separator).

- Encrypted payload using:
  - Key: 32-byte shared secret decapsulated from X-Wing ciphertext
  - Nonce: 12-byte GCM nonce from header
  - AAD: Entire header (including Header MAC field)
- Streaming: Processed in arbitrary chunks (recommended 64 KiB)
- Padding: Optional PKCS#7 on final block for exact size recovery (not required by GCM)

If no payload (empty file), this section is 0 bytes.

## 3. GCM Authentication Tag (Fixed 16 bytes)

The final 16 bytes of the file.

- Authenticates:
  - Entire AES ciphertext
  - Entire header as Additional Authenticated Data (AAD)

## Additional Security Mechanisms
- **Version Binding** (anti-downgrade):
  - Append version byte (0x01) to the AES key before X-Wing encapsulation.
  - On decryption, extract the last byte and verify it matches header version.
- **Header MAC**:
  - Provides early, explicit integrity check before expensive decapsulation.
  - Verified immediately after reading header.

## Parsing Rules
- Implementations MUST reject unknown Key Type or KDF Type values.
- Unknown extension tags MUST be skipped.
- All conditional fields MUST be present exactly as specified when their parent condition is true.
- Header MAC MUST match recomputed value using derived key.
- The GCM tag is located at EOF - 16 bytes; file size MUST be ≥ header size + 16.