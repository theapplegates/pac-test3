#!/bin/bash
# Automation script for SLHDSA256s + MLKEM1024_X448 key generation
# Based on the malte/certbuilder_pk_algos branch

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Function to display usage
usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  generate <email> <prefix>    Generate PQC keys for given email with file prefix
  build                        Build the keygen_sign_verify example
  run                          Run the keygen_sign_verify example
  clean                        Clean generated key files
  help                         Show this help message

Examples:
  $0 generate "me@paulapplegate.com" "paul"
  $0 build
  $0 run

This script uses the following Post-Quantum Cryptography algorithms:
  - Signing: SLH-DSA-256s (SLHDSA256s)
  - Encryption: ML-KEM-1024+X448 (MLKEM1024_X448)
  - Hash: SHA3-512 (V6 default)
  - Profile: V6 (RFC 9580)
EOF
}

# Function to check if we're in the right directory
check_directory() {
    if [ ! -f "Cargo.toml" ] || [ ! -d "openpgp" ]; then
        print_error "Not in the sequoia repository root directory"
        exit 1
    fi
}

# Function to check if we're on the right branch
check_branch() {
    local current_branch=$(git branch --show-current)
    if [ "$current_branch" != "malte/certbuilder_pk_algos" ]; then
        print_warning "Current branch: $current_branch"
        print_warning "Expected branch: malte/certbuilder_pk_algos"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "On correct branch: malte/certbuilder_pk_algos"
    fi
}

# Function to set OpenSSL environment variables
setup_openssl_env() {
    export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
    export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
    export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
    export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
    export LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib
    export DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib
    export RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib"
}

# Function to build the example
build_example() {
    print_info "Building keygen_sign_verify example..."
    setup_openssl_env
    cargo build -p sequoia-openpgp --example keygen_sign_verify \
        --no-default-features --features crypto-openssl,compression
    print_success "Build complete"
}

# Function to run the example
run_example() {
    print_info "Running keygen_sign_verify example..."
    setup_openssl_env
    cargo run -p sequoia-openpgp --example keygen_sign_verify \
        --no-default-features --features crypto-openssl,compression
}

# Function to generate keys using Rust code
generate_keys() {
    local email="$1"
    local prefix="$2"

    if [ -z "$email" ] || [ -z "$prefix" ]; then
        print_error "Email and prefix are required"
        usage
        exit 1
    fi

    print_info "Generating PQC keys for: $email"
    print_info "File prefix: $prefix"
    print_info "Algorithms:"
    echo "    - Signing: SLH-DSA-256s (SLHDSA256s)"
    echo "    - Encryption: ML-KEM-1024+X448 (MLKEM1024_X448)"
    echo "    - Hash: SHA3-512"
    echo "    - Profile: V6 (RFC 9580)"
    echo ""

    # Create a temporary Rust program to generate the keys
    local temp_dir=$(mktemp -d)
    local temp_file="$temp_dir/keygen.rs"

    cat > "$temp_file" <<'RUST_CODE'
use std::io::Write;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::types::*;
use openpgp::serialize::SerializeInto;
use openpgp::serialize::Serialize;
use openpgp::Profile;

fn main() -> openpgp::Result<()> {
    let email = std::env::args().nth(1).expect("Email required");
    let prefix = std::env::args().nth(2).expect("Prefix required");

    // Generate certificate using the new methods
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(format!("{}", email))
        .set_profile(Profile::RFC9580)?  // V6 profile required for PQC
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

    // Export public key
    let public_file = format!("{}_public.asc", prefix);
    let mut public_key_data = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut public_key_data,
            openpgp::armor::Kind::PublicKey
        )?;
        cert.serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write(&public_file, &public_key_data)?;

    // Export secret key
    let secret_file = format!("{}_secret.asc", prefix);
    let mut secret_key_data = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut secret_key_data,
            openpgp::armor::Kind::SecretKey
        )?;
        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write(&secret_file, &secret_key_data)?;

    // Print summary
    println!("✓ Generated keys:");
    println!("  Public: {}", public_file);
    println!("  Secret: {}", secret_file);
    println!("  Fingerprint: {}", cert.fingerprint());
    println!("  Primary key: {:?} (certification + signing)", cert.primary_key().key().pk_algo());

    // Print subkeys
    for (i, key) in cert.keys().subkeys().enumerate() {
        let flags = key.with_policy(&openpgp::policy::StandardPolicy::new(), None)
            .ok()
            .and_then(|k| k.key_flags())
            .unwrap_or(KeyFlags::empty());
        println!("  Subkey {}: {:?} ({:?})",
            i + 1,
            key.key().pk_algo(),
            flags
        );
    }

    // Print file sizes
    println!("  Public key size: {} bytes (~{} KB)",
        public_key_data.len(),
        public_key_data.len() / 1024
    );
    println!("  Secret key size: {} bytes (~{} KB)",
        secret_key_data.len(),
        secret_key_data.len() / 1024
    );

    Ok(())
}
RUST_CODE

    # Build and run the temporary program
    print_info "Building key generation tool..."

    # Save the original directory before changing to temp dir
    local original_dir=$(pwd)
    cd "$temp_dir"

    # Create a minimal Cargo.toml
    cat > "$temp_dir/Cargo.toml" <<EOF
[package]
name = "keygen-temp"
version = "0.1.0"
edition = "2021"

[dependencies]
sequoia-openpgp = { path = "$original_dir/openpgp", default-features = false, features = ["crypto-openssl", "compression"] }
anyhow = "1"
EOF

    # Copy the source to src/main.rs
    mkdir -p src
    mv "$temp_file" src/main.rs

    print_info "Generating keys..."
    if cargo run --quiet -- "$email" "$prefix" 2>&1; then
        print_success "Keys generated successfully"

        # Move generated files back to original directory
        if [ -f "${prefix}_public.asc" ]; then
            mv "${prefix}_public.asc" "$OLDPWD/"
            mv "${prefix}_secret.asc" "$OLDPWD/"
            cd "$OLDPWD"

            print_success "Files saved:"
            ls -lh "${prefix}_public.asc" "${prefix}_secret.asc"
        else
            print_error "Failed to find generated key files"
            cd "$OLDPWD"
            exit 1
        fi
    else
        print_error "Key generation failed"
        cd "$OLDPWD"
        exit 1
    fi

    # Clean up
    rm -rf "$temp_dir"
}

# Function to clean generated files
clean_files() {
    print_info "Cleaning generated key files..."
    rm -f *_public.asc *_secret.asc message_signed.asc
    print_success "Cleaned generated files"
}

# Main script logic
main() {
    local command="${1:-help}"

    case "$command" in
        generate)
            check_directory
            check_branch
            shift
            generate_keys "$@"
            ;;
        build)
            check_directory
            check_branch
            build_example
            ;;
        run)
            check_directory
            check_branch
            run_example
            ;;
        clean)
            clean_files
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            print_error "Unknown command: $command"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Run main with all arguments
main "$@"
