// openpgp/examples/pqc_keygen.rs
//
// Simple CLI tool for generating PQC keys with SLHDSA256s + MLKEM1024_X448
//
// Usage:
//   cargo run --example pqc_keygen -- --userid "Your Name" --email "you@example.com"
//   cargo run --example pqc_keygen -- --userid "Your Name" --email "you@example.com" --output mykey

use std::env;
use sequoia_openpgp as openpgp;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::serialize::SerializeInto;
use openpgp::Profile;

fn print_usage() {
    eprintln!("PQC Key Generator - SLHDSA256s + MLKEM1024_X448");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  cargo run --example pqc_keygen -- --userid NAME --email EMAIL [OPTIONS]");
    eprintln!();
    eprintln!("Required:");
    eprintln!("  --userid NAME    Your name (e.g., 'Paul Applegate')");
    eprintln!("  --email EMAIL    Your email (e.g., 'me@paulapplegate.com')");
    eprintln!();
    eprintln!("Optional:");
    eprintln!("  --output PREFIX  Output file prefix (default: 'key')");
    eprintln!("                   Creates PREFIX_public.asc and PREFIX_secret.asc");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  cargo run --example pqc_keygen -- --userid 'Paul' --email 'me@paulapplegate.com'");
    eprintln!("  cargo run --example pqc_keygen -- --userid 'Paul' --email 'me@paulapplegate.com' --output paul");
    eprintln!();
    eprintln!("Algorithms:");
    eprintln!("  Profile:     V6 (RFC 9580)");
    eprintln!("  Signing:     SLH-DSA-256s (quantum-resistant)");
    eprintln!("  Encryption:  ML-KEM-1024+X448 (quantum-resistant hybrid)");
    eprintln!("  Hash:        SHA3-512");
}

fn main() -> openpgp::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut userid: Option<String> = None;
    let mut email: Option<String> = None;
    let mut output_prefix = "key".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--userid" => {
                i += 1;
                if i < args.len() {
                    userid = Some(args[i].clone());
                }
            }
            "--email" => {
                i += 1;
                if i < args.len() {
                    email = Some(args[i].clone());
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output_prefix = args[i].clone();
                }
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Validate required arguments
    if userid.is_none() || email.is_none() {
        eprintln!("Error: --userid and --email are required\n");
        print_usage();
        std::process::exit(1);
    }

    let userid = userid.unwrap();
    let email = email.unwrap();
    let userid_string = format!("{} <{}>", userid, email);

    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  PQC Key Generator                                     ║");
    println!("║  SLHDSA256s + MLKEM1024_X448                           ║");
    println!("╚════════════════════════════════════════════════════════╝");
    println!();
    println!("Configuration:");
    println!("  User ID:     {}", userid_string);
    println!("  Profile:     V6 (RFC 9580)");
    println!("  Signing:     SLH-DSA-256s");
    println!("  Encryption:  ML-KEM-1024+X448");
    println!("  Hash:        SHA3-512");
    println!();

    // Generate certificate
    println!("Generating certificate...");
    let (cert, _revocation) = CertBuilder::new()
        .set_profile(Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::SLHDSA256s_MLKEM1024_x448)
        .add_userid(userid_string.as_str())
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()?;

    println!("✓ Certificate generated");
    println!("  Fingerprint: {}", cert.fingerprint());
    println!();

    // Verify structure
    println!("Certificate structure:");
    println!("  Primary key: {}", cert.primary_key().key().pk_algo());
    for (i, sk) in cert.keys().subkeys().enumerate() {
        println!("  Subkey {}: {}", i, sk.key().pk_algo());
    }
    println!();

    // Export keys
    let public_file = format!("{}_public.asc", output_prefix);
    let secret_file = format!("{}_secret.asc", output_prefix);

    println!("Exporting keys...");

    let public_asc = cert.armored().to_vec()?;
    std::fs::write(&public_file, &public_asc)?;
    println!("✓ Public key:  {} ({} bytes)", public_file, public_asc.len());

    let secret_asc = cert.as_tsk().armored().to_vec()?;
    std::fs::write(&secret_file, &secret_asc)?;
    println!("✓ Secret key:  {} ({} bytes)", secret_file, secret_asc.len());

    println!();
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SUCCESS!                                              ║");
    println!("╚════════════════════════════════════════════════════════╝");
    println!();
    println!("Your quantum-resistant keys are ready to use!");
    println!();
    println!("Next steps:");
    println!("  - Share the public key: {}", public_file);
    println!("  - Keep the secret key safe: {}", secret_file);
    println!("  - Use with any OpenPGP-compatible tool");

    Ok(())
}
