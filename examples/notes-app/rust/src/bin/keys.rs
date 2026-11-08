//! Creates Konklav's signing keys in a directory, unless they exist:
//! `signing-key.pem` (Ed25519, for access tokens) and `id-token-key.pem`
//! (P-256, for ES256 ID tokens).

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use p256::pkcs8::LineEnding;

fn random() -> [u8; 32] {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).expect("system randomness");
    bytes
}

fn write(path: &Path, pem: &str) {
    if path.exists() {
        println!("{} exists", path.display());
        return;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|e| panic!("creating {}: {e}", path.display()));
    file.write_all(pem.as_bytes()).expect("writing the key");
    println!("wrote {}", path.display());
}

fn main() {
    let directory = std::env::args()
        .nth(1)
        .expect("usage: sso-keys <directory>");
    let directory = Path::new(&directory);

    let signing = ed25519_dalek::SigningKey::from_bytes(&random());
    let pem = signing
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("encoding the Ed25519 key");
    write(&directory.join("signing-key.pem"), &pem);

    let id_token = loop {
        if let Ok(key) = p256::SecretKey::from_slice(&random()) {
            break key;
        }
    };
    let pem = id_token
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encoding the P-256 key");
    write(&directory.join("id-token-key.pem"), &pem);
}
