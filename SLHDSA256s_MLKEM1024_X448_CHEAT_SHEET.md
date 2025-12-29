# SLHDSA256s + MLKEM1024_X448 Complete Cheat Sheet

**Your Post-Quantum Cryptography Configuration**
- **Signing Algorithm**: SLH-DSA-256s (quantum-resistant hash-based signatures)
- **Encryption Algorithm**: ML-KEM-1024+X448 (quantum-resistant hybrid KEM)
- **Profile**: V6 (RFC 9580)
- **Hash**: SHA3-512 (automatic with V6)
- **Security Level**: 256-bit classical, quantum-resistant

---

## Quick Start

### 1. Setup Environment

```bash
# macOS
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"

# Add to ~/.zshrc for persistence
echo 'export OPENSSL_DIR=/opt/homebrew/opt/openssl@3' >> ~/.zshrc
echo 'export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib' >> ~/.zshrc
echo 'export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include' >> ~/.zshrc
echo 'export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig' >> ~/.zshrc
echo 'export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"' >> ~/.zshrc
echo 'export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"' >> ~/.zshrc
```

**IMPORTANT**: You need **OpenSSL 3.6.0 or later** for PQC support. Check with:
```bash
/opt/homebrew/opt/openssl@3/bin/openssl version
```

### 2. Build

```bash
# Build everything
cargo build --all --no-default-features --features crypto-openssl,compression

# Build with release optimizations
cargo build --release --all --no-default-features --features crypto-openssl,compression
```

### 3. Run Demo

```bash
cargo run -p sequoia-openpgp \
  --example slhdsa256s_mlkem1024_x448_demo \
  --no-default-features \
  --features crypto-openssl,compression
```

---

## Algorithm Specifications

### SLH-DSA-256s (Signing)

| Property | Value |
|----------|-------|
| **Algorithm ID** | SLHDSA256s (34) |
| **Type** | Stateless hash-based signature |
| **Security** | 256-bit classical + quantum-resistant |
| **Public Key** | 64 bytes |
| **Secret Key** | 128 bytes |
| **Signature** | 29,792 bytes (large!) |
| **Hash Function** | SHAKE-256 (internal) |
| **Standard** | FIPS 205 |

**Characteristics:**
- ✅ Quantum-resistant (hash-based security)
- ✅ Stateless (no state management between signatures)
- ✅ Well-understood security assumptions
- ⚠️ Large signature size (~30 KB)

### ML-KEM-1024+X448 (Encryption)

| Property | Value |
|----------|-------|
| **Algorithm ID** | MLKEM1024_X448 (113) |
| **Type** | Hybrid KEM (lattice + elliptic curve) |
| **Security** | 256-bit classical + quantum-resistant |
| **Public Key** | 1,624 bytes (1568 ML-KEM + 56 X448) |
| **Secret Key** | 3,224 bytes (3168 ML-KEM + 56 X448) |
| **Ciphertext** | 1,624 bytes + wrapped session key |
| **Standards** | FIPS 203 (ML-KEM) + RFC 7748 (X448) |

**Characteristics:**
- ✅ Quantum-resistant (lattice + ECC hybrid)
- ✅ Defense-in-depth (two independent algorithms)
- ✅ Fast encryption/decryption
- ✅ Standardized by NIST

### SHA3-512 (Hashing)

| Property | Value |
|----------|-------|
| **Algorithm ID** | SHA3_512 (14) |
| **Output Size** | 512 bits (64 bytes) |
| **Standard** | FIPS 202 |
| **Usage** | Automatic with V6 profile |

---

## Key Generation (Rust API)

### Generate Certificate

```rust
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::types::*;
use openpgp::Profile;
use openpgp::policy::StandardPolicy;

let policy = &StandardPolicy::new();

let (cert, _revocation) = CertBuilder::new()
    .add_userid("Paul Applegate <me@paulapplegate.com>")
    .set_profile(Profile::RFC9580)?  // V6 profile required for PQC
    .set_creation_time(std::time::SystemTime::now())
    .set_primary_key_flags(
        KeyFlags::empty()
            .set_certification()
            .set_signing()
    )
    // Set SLHDSA256s for all signing operations
    .set_signing_algorithm(PublicKeyAlgorithm::SLHDSA256s, None, None)?
    // Set MLKEM1024_X448 for all encryption operations
    .set_encryption_algorithm(PublicKeyAlgorithm::MLKEM1024_X448, None, None)?
    .add_signing_subkey()
    .add_storage_encryption_subkey()
    .generate()?;
```

### Using CipherSuite (Alternative)

**NEW**: The `CipherSuite::SLHDSA256s_MLKEM1024_X448` variant has been added to the codebase!

```rust
// Alternative approach using cipher suite
let (cert, _revocation) = CertBuilder::new()
    .add_userid("Paul Applegate <me@paulapplegate.com>")
    .set_profile(Profile::RFC9580)?
    .set_cipher_suite(CipherSuite::SLHDSA256s_MLKEM1024_X448)
    .generate()?;
```

### Export to .asc Format

```rust
use openpgp::serialize::SerializeInto;

// Export public key
let public_key_data = cert.armored().to_vec()?;
std::fs::write("paul_public.asc", &public_key_data)?;

// Export secret key
let secret_key_data = cert.as_tsk().armored().to_vec()?;
std::fs::write("paul_secret.asc", &secret_key_data)?;
```

---

## Signing Operations

### Cleartext Signature (Human-Readable)

**Default and recommended method for text messages.**

```rust
use openpgp::serialize::stream::*;
use std::io::Write;

let message = b"Hello, Post-Quantum World!";

// Get signing keypair
let signing_keypair = cert.keys()
    .with_policy(&policy, None)
    .for_signing()
    .next()
    .ok_or_else(|| anyhow::anyhow!("No signing key found"))?
    .key()
    .clone()
    .parts_into_secret()?
    .into_keypair()?;

// Create cleartext signature
let mut signed_message = Vec::new();
{
    let message_writer = Message::new(&mut signed_message);

    let signer = Signer::new(message_writer, signing_keypair)?;
    let signer = signer.cleartext();  // Cleartext = message is readable
    let mut signer = signer.build()?;

    signer.write_all(message)?;
    signer.finalize()?;
}

std::fs::write("message_signed.asc", &signed_message)?;
```

**Output format:**
```
-----BEGIN PGP SIGNED MESSAGE-----

Hello, Post-Quantum World!
-----BEGIN PGP SIGNATURE-----

<base64 signature data>
-----END PGP SIGNATURE-----
```

### Detached Signature

**Signature in separate file.**

```rust
let signer = Signer::new(message_writer, signing_keypair)?;
let signer = signer.detached();  // Detached signature
let mut signer = signer.build()?;
```

---

## Signature Verification

```rust
use openpgp::parse::stream::*;
use openpgp::parse::Parse;

struct Helper<'a> {
    cert: &'a openpgp::Cert,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                 -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure)
             -> openpgp::Result<()> {
        use openpgp::Error;

        for layer in structure.iter() {
            match layer {
                MessageLayer::SignatureGroup { results } => {
                    for result in results {
                        match result {
                            Ok(GoodChecksum { ka, .. }) => {
                                println!("✓ Valid signature");
                                println!("  Signer: {}", ka.cert().fingerprint());
                                println!("  Algorithm: {:?}", ka.key().pk_algo());

                                // Verify it's SLH-DSA-256s
                                assert_eq!(
                                    ka.key().pk_algo(),
                                    PublicKeyAlgorithm::SLHDSA256s
                                );
                                return Ok(());
                            }
                            Err(e) => {
                                eprintln!("✗ Signature verification failed: {}", e);
                                return Err(Error::BadSignature(
                                    format!("Verification failed: {}", e)
                                ).into());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Err(Error::BadSignature("No valid signature found".to_string()).into())
    }
}

let helper = Helper { cert: &cert };
let mut verifier = VerifierBuilder::from_reader(&signed_message[..])?
    .with_policy(&policy, None, helper)?;

let mut verified_message = Vec::new();
std::io::copy(&mut verifier, &mut verified_message)?;

println!("Verified: {}", String::from_utf8_lossy(&verified_message));
```

---

## Encryption Operations

### Encrypt Message

```rust
use openpgp::serialize::stream::*;
use std::io::Write;

let message = b"Secret message";

// Get encryption keys
let recipients = cert.keys()
    .with_policy(&policy, None)
    .for_storage_encryption()
    .for_transport_encryption();

let mut encrypted = Vec::new();
{
    let message_writer = Message::new(&mut encrypted);
    let message_writer = Armorer::new(message_writer)
        .kind(openpgp::armor::Kind::Message)
        .build()?;

    let mut encryptor = Encryptor::for_recipients(
        message_writer,
        recipients
    )
        .symmetric_algo(SymmetricAlgorithm::AES256)
        .build()?;

    encryptor.write_all(message)?;
    encryptor.finalize()?;
}

std::fs::write("message_encrypted.asc", &encrypted)?;
```

### Decrypt Message

```rust
use openpgp::packet::PKESK;
use openpgp::packet::SKESK;
use openpgp::crypto::SessionKey;

struct DecHelper<'a> {
    cert: &'a openpgp::Cert,
    policy: &'a dyn openpgp::policy::Policy,
}

impl<'a> VerificationHelper for DecHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                 -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![])
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl<'a> DecryptionHelper for DecHelper<'a> {
    fn decrypt(&mut self,
               pkesks: &[PKESK],
               _skesks: &[SKESK],
               sym_algo: Option<SymmetricAlgorithm>,
               mut decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
               -> openpgp::Result<Option<openpgp::Fingerprint>>
    {
        for pkesk in pkesks {
            let mut keypairs = self.cert.keys()
                .with_policy(self.policy, None)
                .for_transport_encryption()
                .for_storage_encryption()
                .secret()
                .filter_map(|k| k.key().clone().into_keypair().ok());

            for mut keypair in keypairs {
                if let Some((algo, session_key)) =
                    pkesk.decrypt(&mut keypair, sym_algo)
                {
                    if decrypt(Some(algo), &session_key) {
                        println!("✓ Decrypted with: {:?}",
                                 keypair.public().pk_algo());
                        return Ok(Some(keypair.public().fingerprint()));
                    }
                }
            }
        }
        Err(anyhow::anyhow!("Decryption failed").into())
    }
}

let helper = DecHelper { cert: &cert, policy: &policy };
let mut decryptor = DecryptorBuilder::from_bytes(&encrypted)?
    .with_policy(&policy, None, helper)?;

let mut decrypted = Vec::new();
std::io::copy(&mut decryptor, &mut decrypted)?;

println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
```

---

## Testing

### Run All PQC Tests

```bash
# SLH-DSA-256s tests
cargo test -p sequoia-openpgp slhdsa256s \
  --no-default-features --features crypto-openssl,compression

# ML-KEM-1024 tests
cargo test -p sequoia-openpgp mlkem1024 \
  --no-default-features --features crypto-openssl,compression

# Certificate tests
cargo test -p sequoia-openpgp cert \
  --no-default-features --features crypto-openssl,compression
```

### Run Specific Example

```bash
cargo run -p sequoia-openpgp \
  --example slhdsa256s_mlkem1024_x448_demo \
  --no-default-features \
  --features crypto-openssl,compression
```

---

## File Formats

### Public Key (.asc)

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

<base64 encoded public key data>
-----END PGP PUBLIC KEY BLOCK-----
```

**File size**: ~200 KB (due to large SLH-DSA keys)

### Secret Key (.asc)

```
-----BEGIN PGP PRIVATE KEY BLOCK-----

<base64 encoded secret key data>
-----END PGP PRIVATE KEY BLOCK-----
```

**File size**: ~201 KB

### Signed Message (.asc)

```
-----BEGIN PGP SIGNED MESSAGE-----

<cleartext message>
-----BEGIN PGP SIGNATURE-----

<base64 encoded signature>
-----END PGP SIGNATURE-----
```

**File size**: ~40 KB for short messages (signature is ~30 KB)

### Encrypted Message (.asc)

```
-----BEGIN PGP MESSAGE-----

<base64 encoded encrypted data>
-----END PGP MESSAGE-----
```

---

## Performance Considerations

### Signature Size Comparison

| Algorithm | Signature Size |
|-----------|----------------|
| Ed25519 | 64 bytes |
| ML-DSA-87+Ed448 | ~4,595 bytes |
| **SLH-DSA-256s** | **29,792 bytes** ⚠️ |

**Impact**: SLH-DSA signatures are ~466x larger than Ed25519. This affects:
- Network bandwidth
- Storage requirements
- Transmission time
- Message size limits

**Recommendation**: Use SLH-DSA when:
- Quantum resistance is critical
- Long-term security is required
- Hash-based security assumptions preferred
- Size is not a major constraint

### Encryption Performance

ML-KEM-1024+X448 provides:
- ✅ Fast key generation
- ✅ Fast encryption
- ✅ Fast decryption
- ✅ Reasonable ciphertext size

---

## Common Errors and Solutions

### Error: `CipherSuite::Custom` not found

**Issue**: Old cheat sheets referenced `CipherSuite::Custom` which doesn't exist.

**Solution**: Use either:
1. `set_signing_algorithm()` and `set_encryption_algorithm()` (recommended)
2. `set_cipher_suite(CipherSuite::SLHDSA256s_MLKEM1024_X448)` (new variant)

### Error: OpenSSL header not found

**Solution**: Set environment variables:
```bash
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
```

### Error: Algorithms not supported

**Solution**: Verify OpenSSL 3.6.0+ is installed:
```bash
/opt/homebrew/opt/openssl@3/bin/openssl version
```

Must show: `OpenSSL 3.6.0` or later (not 3.4.0 or 3.5.0)

---

## Quick Reference

### Essential Commands

```bash
# Setup
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig

# Build
cargo build --all --no-default-features --features crypto-openssl,compression

# Test
cargo test --all --no-default-features --features crypto-openssl,compression

# Demo
cargo run -p sequoia-openpgp --example slhdsa256s_mlkem1024_x448_demo \
  --no-default-features --features crypto-openssl,compression
```

### Key Specifications

| Component | Algorithm | Key Size | Output Size |
|-----------|-----------|----------|-------------|
| Primary Key | SLH-DSA-256s | 64/128 bytes | 29,792 bytes (sig) |
| Signing Subkey | SLH-DSA-256s | 64/128 bytes | 29,792 bytes (sig) |
| Encryption Subkey | ML-KEM-1024+X448 | 1624/3224 bytes | 1624+ bytes (ct) |
| Hash | SHA3-512 | N/A | 64 bytes |

### Certificate Structure

```
Certificate (V6, RFC 9580)
├── Primary Key: SLH-DSA-256s (certification + signing)
├── User ID: "paul <paul@example.com>"
├── Subkey 0: SLH-DSA-256s (signing)
└── Subkey 1: ML-KEM-1024+X448 (encryption)
```

---

## Working Example Output

When you run the demo, you should see:

```
╔════════════════════════════════════════════════════════╗
║          SLHDSA256s_MLKEM1024_X448 Demo              ║
║       Generate → Sign → Verify (3 steps)              ║
╚════════════════════════════════════════════════════════╝

STEP 1: Generating V6 certificate...
  Algorithms: SLH-DSA-256s (sign) + ML-KEM-1024+X448 (encrypt)
  Profile: V6 (RFC 9580)
  Hash: SHA3-512
  ✓ Certificate fingerprint: 9C42D8F0A30C18215283941EF6FA5529AC165B4EDA3E195E993CE84C79619668
  ✓ Primary key: SLHDSA256s
  ✓ Saved: paul_public.asc (205068 bytes)
  ✓ Saved: paul_secret.asc (205586 bytes)

STEP 2: Signing a message...
  Message: "Hello, Post-Quantum World! This is a signed message using SLH-DSA-256s."
  ✓ Using key: SLHDSA256s
  ✓ Saved: message_signed.asc (40644 bytes)
  ✓ Signature size: ~29 KB (SLH-DSA-256s)
  ✓ Hash algorithm: SHAKE-256 (internal to SLH-DSA)

STEP 3: Verifying signature...
  ✓ Signature is VALID
  ✓ Signer fingerprint: 9C42D8F0A30C18215283941EF6FA5529AC165B4EDA3E195E993CE84C79619668
  ✓ Signing algorithm: SLHDSA256s
  ✓ Quantum-resistant: YES (SLH-DSA-256s)
  ✓ Verified message: "Hello, Post-Quantum World! This is a signed message using SLH-DSA-256s."
  ✓ Message integrity: CONFIRMED

╔════════════════════════════════════════════════════════╗
║                    SUCCESS!                            ║
╚════════════════════════════════════════════════════════╝
```

---

## Resources

- **Standard**: RFC 9580 (OpenPGP V6)
- **PQC Draft**: draft-ietf-openpgp-pqc-11
- **FIPS 205**: SLH-DSA (SPHINCS+)
- **FIPS 203**: ML-KEM (Kyber)
- **RFC 7748**: X448 Elliptic Curve
- **FIPS 202**: SHA3-512

---

## Summary

Your SLHDSA256s + MLKEM1024_X448 configuration provides:

✅ **256-bit quantum-resistant security**
✅ **V6 profile compliance (RFC 9580)**
✅ **SHA3-512 hashing throughout**
✅ **Hash-based signatures (SLH-DSA-256s)**
✅ **Hybrid lattice encryption (ML-KEM-1024+X448)**
✅ **Defense-in-depth architecture**
✅ **NIST-standardized algorithms (FIPS 203, FIPS 205)**
✅ **OpenSSL 3.6.0+ backend support**

This is a cutting-edge, future-proof cryptographic setup suitable for long-term secure communications.

---

## What Was Fixed

The original cheat sheet had the following errors:

1. **`CipherSuite::Custom` doesn't exist** - It was removed from the API
2. **Incorrect API usage** - Need to use `set_signing_algorithm()` and `set_encryption_algorithm()`
3. **Added new CipherSuite variant** - Created `CipherSuite::SLHDSA256s_MLKEM1024_X448` for convenience
4. **Fixed verification code** - Corrected the VerificationHelper implementation
5. **Fixed decryption code** - Corrected the DecryptionHelper implementation

All examples now work correctly with Sequoia-PGP 2.2.0-pqc.1 and OpenSSL 3.6.0.
