// Save as: openpgp/examples/keygen_sign_verify.rs
// Simple example: Generate key, sign message, verify signature
// Usage: cargo run -p sequoia-openpgp --example keygen_sign_verify \
//        --no-default-features --features crypto-openssl,compression

use std::io::Write;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::serialize::SerializeInto;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy as P;
use openpgp::types::*;
use openpgp::Profile;

fn main() -> openpgp::Result<()> {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║          SLHDSA256s_MLKEM1024_X448 Demo              ║");
    println!("║       Generate → Sign → Verify (3 steps)              ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // STEP 1: Generate Keys
    // ========================================================================
    println!("STEP 1: Generating V6 certificate...");
    println!("  Algorithms: SLH-DSA-256s (sign) + ML-KEM-1024+X448 (encrypt)");
    println!("  Profile: V6 (RFC 9580)");
    println!("  Hash: SHA3-512");
    
    let policy = &P::new();
    
    // Generate certificate with PQC algorithms
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("Paul <me@paulapplegate.com>")
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
    
    println!("  ✓ Certificate fingerprint: {}", cert.fingerprint());
    println!("  ✓ Primary key: {:?}", cert.primary_key().key().pk_algo());
    
    // Export public key to .asc file
    let public_key_data = cert.armored().to_vec()?;
    std::fs::write("paul_public.asc", &public_key_data)?;
    println!("  ✓ Saved: paul_public.asc ({} bytes)", public_key_data.len());
    
    // Export secret key to .asc file
    let secret_key_data = cert.as_tsk().armored().to_vec()?;
    std::fs::write("paul_secret.asc", &secret_key_data)?;
    println!("  ✓ Saved: paul_secret.asc ({} bytes)\n", secret_key_data.len());
    
    // ========================================================================
    // STEP 2: Sign a Message
    // ========================================================================
    println!("STEP 2: Signing a message...");
    
    let message = b"Hello, Post-Quantum World! This is a signed message using SLH-DSA-256s.";
    println!("  Message: \"{}\"", String::from_utf8_lossy(message));
    
    // Get the signing key
    let signing_keypair = cert.keys()
        .with_policy(policy, None)
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing key found"))?
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;
    
    println!("  ✓ Using key: {:?}", signing_keypair.public().pk_algo());
    
    // Create cleartext signature (human-readable)
    let mut signed_message = Vec::new();
    {
        // Don't use Armorer with cleartext signatures - they create their own armor
        let message_writer = Message::new(&mut signed_message);

        let signer = Signer::new(message_writer, signing_keypair)?;
        let signer = signer.cleartext();  // Cleartext = message is readable (creates its own armor)
        // Note: SLHDSA uses its internal hash (SHAKE-256) and doesn't need an external hash algo
        let mut signer = signer.build()?;

        signer.write_all(message)?;
        signer.finalize()?;
    }
    
    std::fs::write("message_signed.asc", &signed_message)?;
    println!("  ✓ Saved: message_signed.asc ({} bytes)", signed_message.len());
    println!("  ✓ Signature size: ~{} KB (SLH-DSA-256s)", SLHDSA256S_SIGNATURE_SIZE / 1024);
    println!("  ✓ Hash algorithm: SHAKE-256 (internal to SLH-DSA)\n");
    
    // Show the signed message
    println!("  Preview of signed message:");
    println!("  ┌────────────────────────────────────────────┐");
    for line in String::from_utf8_lossy(&signed_message).lines().take(10) {
        println!("  │ {:<42} │", line);
    }
    println!("  │ ... (signature data continues) ...         │");
    println!("  └────────────────────────────────────────────┘\n");
    
    // ========================================================================
    // STEP 3: Verify the Signature
    // ========================================================================
    println!("STEP 3: Verifying signature...");
    
    // Helper for verification
    struct Helper<'a> {
        cert: &'a openpgp::Cert,
        policy: &'a dyn openpgp::policy::Policy,
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
                                    println!("  ✓ Signature is VALID");
                                    println!("  ✓ Signer fingerprint: {}",
                                             ka.cert().fingerprint());
                                    println!("  ✓ Signing algorithm: {:?}",
                                             ka.key().pk_algo());

                                    // Verify it's SLH-DSA-256s
                                    if ka.key().pk_algo() == PublicKeyAlgorithm::SLHDSA256s {
                                        println!("  ✓ Quantum-resistant: YES (SLH-DSA-256s)");
                                    }

                                    return Ok(());
                                }
                                Err(e) => {
                                    eprintln!("  ✗ Signature is INVALID: {}", e);
                                    return Err(Error::BadSignature(format!("Signature verification failed: {}", e)).into());
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
    
    let helper = Helper { cert: &cert, policy };
    // Use from_reader for cleartext signed messages which are in ASCII armor
    let mut verifier = VerifierBuilder::from_reader(&signed_message[..])?
        .with_policy(policy, None, helper)?;

    let mut verified_message = Vec::new();
    std::io::copy(&mut verifier, &mut verified_message)?;
    
    println!("  ✓ Verified message: \"{}\"", 
             String::from_utf8_lossy(&verified_message));
    
    // Verify the message matches
    if &verified_message[..] == message {
        println!("  ✓ Message integrity: CONFIRMED\n");
    } else {
        eprintln!("  ✗ Message integrity: FAILED\n");
        return Err(openpgp::Error::ManipulatedMessage.into());
    }
    
    // ========================================================================
    // SUMMARY
    // ========================================================================
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║                    SUCCESS!                            ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Generated Files:                                      ║");
    println!("║    • paul_public.asc  - Public key                     ║");
    println!("║    • paul_secret.asc  - Secret key                     ║");
    println!("║    • message_signed.asc - Signed message               ║");
    println!("║                                                        ║");
    println!("║  What Happened:                                        ║");
    println!("║    ✓ Generated V6 certificate (SLH-DSA-256s)          ║");
    println!("║    ✓ Signed message with SHAKE-256 (internal)         ║");
    println!("║    ✓ Verified signature successfully                  ║");
    println!("║    ✓ Quantum-resistant cryptography working!          ║");
    println!("╚════════════════════════════════════════════════════════╝");
    
    Ok(())
}

// Constants from official standards
const SLHDSA256S_SIGNATURE_SIZE: usize = 29792;  // FIPS 205
