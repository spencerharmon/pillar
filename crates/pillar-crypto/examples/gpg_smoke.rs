//! Manual gpg-interop smoke: emits a cell key, a user key certified by the cell
//! (a real tsig WoT edge), and a detached-signing demo, to files the caller pipes
//! into the real `gpg` binary. Run: `cargo run -p pillar-crypto --example gpg_smoke -- <outdir>`.

use pillar_crypto::openpgp::{TransferableKey, TrustCertification};
use pillar_crypto::principal::principal_from_seed;
use pillar_crypto::Seed;

fn main() {
    let outdir = std::env::args().nth(1).expect("usage: gpg_smoke <outdir>");
    let created = 1_724_800_000u32;

    let (cell_pub, cell_sec) =
        principal_from_seed(&Seed::from_bytes(b"cell-example-seed".to_vec())).unwrap();
    let (user_pub, user_sec) =
        principal_from_seed(&Seed::from_bytes(b"user-spencer-seed".to_vec())).unwrap();

    let cell_key = TransferableKey {
        uid: "cell:example (pillar cell key) <cell@example.com>".to_owned(),
        created_secs: created,
        signing_pub: cell_pub.signing.clone(),
        signing_sec: Some(cell_sec.signing.clone()),
        sealing_pub: cell_pub.sealing.clone(),
        certifications: vec![],
    };

    let user_key = TransferableKey {
        uid: "user:spencer <spencer@example.com>".to_owned(),
        created_secs: created,
        signing_pub: user_pub.signing.clone(),
        signing_sec: Some(user_sec.signing.clone()),
        sealing_pub: user_pub.sealing.clone(),
        certifications: vec![TrustCertification {
            issuer_signing_pub: cell_pub.signing.clone(),
            issuer_signing_sec: cell_sec.signing.clone(),
            created_secs: created,
            trust_level: 1,
            trust_amount: 120,
        }],
    };

    std::fs::write(
        format!("{outdir}/cell-public.asc"),
        cell_key.export_public_armored().unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("{outdir}/user-secret.asc"),
        user_key.export_secret_armored().unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("{outdir}/user-public.asc"),
        user_key.export_public_armored().unwrap(),
    )
    .unwrap();
    println!("cell fpr:  {}", cell_key.fingerprint_hex());
    println!("user fpr:  {}", user_key.fingerprint_hex());
}
