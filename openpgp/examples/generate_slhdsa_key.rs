// Quick key generator for SLHDSA256s_MLKEM1024_X448
use sequoia_openpgp as openpgp;
use openpgp::cert::CertBuilder;
use openpgp::crypto::Password;
use openpgp::types::CipherSuite;

fn main() -> openpgp::Result<()> {
    // Generate the certificate
    let (cert, _) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::SLHDSA256s_MLKEM1024_x448)
        .add_userid("Paul <me@paulapplegate.com>")
        .generate()?;

    // Export armored keys
    let public_asc = cert.armored().to_vec()?;
    let secret_asc = cert.clone()
        .unlock(|| Password::from(""))
        .unwrap()
        .armored()
        .to_vec()?;

    // Write to files
    std::fs::write("paul_slhdsa_public.asc", &public_asc)?;
    std::fs::write("paul_slhdsa_secret.asc", &secret_asc)?;

    println!("✓ Generated certificate with SLHDSA256s_MLKEM1024_X448");
    println!("  Fingerprint: {}", cert.fingerprint());
    println!("  Public key: paul_slhdsa_public.asc ({} bytes)", public_asc.len());
    println!("  Secret key: paul_slhdsa_secret.asc ({} bytes)", secret_asc.len());

    Ok(())
}
