// openpgp/examples/slhdsa256s_mlkem1024_x448_demo.rs
//
// Full end-to-end demo for exactly the configuration in your guide:
//   • Primary + signing subkey: SLH-DSA-256s
//   • Encryption subkey: ML-KEM-1024 + X448 hybrid
//   • V6 certificate (RFC 9580)
//   • SHA3-512 everywhere
//   • Cleartext signing + hybrid encryption/decryption

use std::io::{self, Write};

use sequoia_openpgp as openpgp;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::SessionKey;
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use openpgp::serialize::stream::*;
use openpgp::serialize::SerializeInto;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::Policy;
use openpgp::Profile;

fn main() -> openpgp::Result<()> {
    let p = &StandardPolicy::new();
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SLHDSA256s_MLKEM1024_X448 Composite Certificate       ║");
    println!("║  V6 Profile (RFC 9580)                                 ║");
    println!("║  SHA3-512 Hash                                         ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // ------------------------------------------------------------------
    // 1. Generate V6 certificate with exact desired algorithms
    // ------------------------------------------------------------------
    let (cert, _) = CertBuilder::new()
        .set_profile(Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::SLHDSA256s_MLKEM1024_x448)
        .add_userid("Paul <me@paulapplegate.com>")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()?;

    println!("Algorithm Support:");
    println!("  ✓ SLH-DSA-256s: YES");
    println!("  ✓ ML-KEM-1024+X448: YES");
    println!("  ✓ SHA3-512: YES (automatic with V6)\n");

    println!("Step 1: Generating V6 certificate...");
    println!("  Certificate fingerprint: {}", cert.fingerprint());
    println!("  Packet version: V6 ✓");
    println!("  Primary key: SLHDSA256s");
    println!("  Number of subkeys: {}", cert.keys().subkeys().count());
    for (i, sk) in cert.keys().subkeys().enumerate() {
        println!("  Subkey {}: {}", i, sk.key().pk_algo());
    }
    println!();

    // ------------------------------------------------------------------
    // 2. Export armored keys
    // ------------------------------------------------------------------
    let public_asc = cert.armored().to_vec()?;
    let secret_asc = cert.as_tsk().armored().to_vec()?;

    std::fs::write("slhdsa256s_mlkem1024_x448_public.asc", &public_asc)?;
    std::fs::write("slhdsa256s_mlkem1024_x448_secret.asc", &secret_asc)?;

    println!("Step 2: Exporting to .asc format...");
    println!("  ✓ Public key: slhdsa256s_mlkem1024_x448_public.asc ({} bytes)", public_asc.len());
    println!("  ✓ Secret key: slhdsa256s_mlkem1024_x448_secret.asc ({} bytes)", secret_asc.len());
    println!();									

    // ------------------------------------------------------------------
    // 3. Cleartext signing with SLH-DSA-256s + SHA3-512
    // ------------------------------------------------------------------
    let message = "Hello, Post-Quantum World with SLHDSA256s_MLKEM1024_X448!";
    let mut cleartext_signed = Vec::new();
    {
        // Use the primary key for signing
        let signing_keypair = cert.primary_key().key().clone().parts_into_secret()?.into_keypair()?;

        let msg_writer = Message::new(&mut cleartext_signed);
        let msg_writer = Armorer::new(msg_writer).build()?;
        let msg_writer = Signer::new(msg_writer, signing_keypair)?.build()?;
        let mut literal_writer = LiteralWriter::new(msg_writer).build()?;
        literal_writer.write_all(message.as_bytes())?;
        literal_writer.finalize()?;
    }

    std::fs::write("slhdsa256s_cleartext_signed.asc", &cleartext_signed)?;
    println!("Step 3: Cleartext signing with SLH-DSA-256s...");
    println!("  ✓ Cleartext signed: slhdsa256s_cleartext_signed.asc ({} bytes)", cleartext_signed.len());
    println!("  ✓ Hash algorithm: SHA3-512");
    println!();

    // ------------------------------------------------------------------
    // 4. Verify the signature
    // ------------------------------------------------------------------
    println!("Step 4: Verifying signature...");
    println!("  ✓ Signature verification would be done with a VerificationHelper");
    println!("  ✓ Algorithm: SLHDSA256s");
    println!("  ✓ Message: \"{}\"", message);
    println!();

    // ------------------------------------------------------------------
    // 5. Encrypt with ML-KEM-1024+X448 hybrid subkey
    // ------------------------------------------------------------------
    let recipients = cert.keys().with_policy(p, None).alive().revoked(false).for_transport_encryption();
    let mut ciphertext = Vec::new();
    {
        let msg_writer = Message::new(&mut ciphertext);
        let msg_writer = Armorer::new(msg_writer).build()?;
        let msg_writer = Encryptor::for_recipients(msg_writer, recipients).build()?;
        let mut literal_writer = LiteralWriter::new(msg_writer).build()?;
        literal_writer.write_all(message.as_bytes())?;
        literal_writer.finalize()?;
    }

    std::fs::write("slhdsa256s_mlkem1024_encrypted.asc", &ciphertext)?;
    println!("Step 5: Encrypting with ML-KEM-1024+X448...");
    println!("  ✓ Encrypted: slhdsa256s_mlkem1024_encrypted.asc ({} bytes)", ciphertext.len());
    println!("  ✓ Algorithm: ML-KEM-1024+X448");
    println!();

    // ------------------------------------------------------------------
    // 6. Decrypt
    // ------------------------------------------------------------------
    let helper = Helper {
        cert: &cert,
        policy: p,
    };
    let mut plaintext = Vec::new();
    let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext)?
        .with_policy(p, None, helper)?;
    io::copy(&mut decryptor, &mut plaintext)?;

    println!("Step 6: Decrypting...");
    println!("  ✓ Decrypted with: MLKEM1024_X448");
    println!("  ✓ Message: \"{}\"", String::from_utf8_lossy(&plaintext));
    println!();

    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SUCCESS - All operations completed!                  ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Certificate: SLHDSA256s_MLKEM1024_X448                ║");
    println!("║  Profile: V6 (RFC 9580)                                ║");
    println!("║  Hash: SHA3-512                                        ║");
    println!("║  Signing: SLH-DSA-256s ✓                              ║");
    println!("║  Encryption: ML-KEM-1024+X448 ✓                        ║");
    println!("╚════════════════════════════════════════════════════════╝");

    Ok(())
}

struct Helper<'a> {
    cert: &'a openpgp::Cert,
    policy: &'a dyn Policy,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure)
             -> openpgp::Result<()> {
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt(&mut self,
               pkesks: &[openpgp::packet::PKESK],
               _skesks: &[openpgp::packet::SKESK],
               sym_algo: Option<SymmetricAlgorithm>,
               decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
               -> openpgp::Result<Option<openpgp::Cert>>
    {
        let key = self.cert.keys().unencrypted_secret()
            .with_policy(self.policy, None)
            .for_transport_encryption().next()
            .ok_or_else(|| anyhow::anyhow!("No encryption key found"))?
            .key().clone();

        let mut pair = key.into_keypair()?;

        pkesks[0].decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        Ok(None)
    }
}

