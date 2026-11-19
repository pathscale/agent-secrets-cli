//! Shared split-custody seed sealing for package, fs-verity, association, recovery and mint keys.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use crate::eyre::{Result, ensure, eyre};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"PAYSSEAL";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SEED_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MAX_PURPOSE_LEN: usize = 32;

pub fn generate_passphrase() -> Result<Zeroizing<[u8; 32]>> {
    let mut passphrase = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *passphrase)
        .map_err(|_| eyre!("OS random passphrase generation failed"))?;
    Ok(passphrase)
}

pub fn seal_seed(seed: &[u8; SEED_LEN], passphrase: &[u8; 32], purpose: &str) -> Result<Vec<u8>> {
    validate_purpose(purpose)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| eyre!("OS random sealing salt generation failed"))?;
    getrandom::fill(&mut nonce).map_err(|_| eyre!("OS random sealing nonce generation failed"))?;

    let mut header = Vec::with_capacity(10 + purpose.len() + SALT_LEN + NONCE_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(purpose.len() as u8);
    header.extend_from_slice(purpose.as_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let key = derive_key(passphrase, &salt, purpose)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| eyre!("could not initialize seed sealing"))?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: seed,
                aad: &header,
            },
        )
        .map_err(|_| eyre!("could not seal seed"))?;

    let mut blob = header;
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub fn unseal_seed(
    blob: &[u8],
    passphrase: &[u8; 32],
    purpose: &str,
) -> Result<Zeroizing<[u8; SEED_LEN]>> {
    validate_purpose(purpose)?;
    ensure!(blob.len() >= 10, "sealed seed blob is truncated");
    ensure!(
        blob.get(..MAGIC.len()) == Some(MAGIC.as_slice()),
        "sealed seed blob has an invalid header"
    );
    ensure!(
        blob[8] == VERSION,
        "sealed seed blob version is unsupported"
    );

    let purpose_len = blob[9] as usize;
    ensure!(
        purpose_len > 0 && purpose_len <= MAX_PURPOSE_LEN,
        "sealed seed purpose length is invalid"
    );
    let purpose_start = 10;
    let purpose_end = purpose_start + purpose_len;
    let salt_end = purpose_end + SALT_LEN;
    let nonce_end = salt_end + NONCE_LEN;
    ensure!(
        blob.len() == nonce_end + SEED_LEN + TAG_LEN,
        "sealed seed blob length is invalid"
    );
    ensure!(
        blob.get(purpose_start..purpose_end) == Some(purpose.as_bytes()),
        "sealed seed purpose does not match"
    );

    let salt = &blob[purpose_end..salt_end];
    let nonce: [u8; NONCE_LEN] = blob[salt_end..nonce_end]
        .try_into()
        .map_err(|_| eyre!("sealed seed nonce has the wrong length"))?;
    let key = derive_key(passphrase, salt, purpose)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| eyre!("could not initialize seed unsealing"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &blob[nonce_end..],
                    aad: &blob[..nonce_end],
                },
            )
            .map_err(|_| eyre!("sealed seed authentication failed"))?,
    );
    ensure!(
        plaintext.len() == SEED_LEN,
        "unsealed seed length is invalid"
    );

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

fn derive_key(passphrase: &[u8; 32], salt: &[u8], purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), passphrase);
    let info = format!("pays-sealed-seed-v1:{purpose}");
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(info.as_bytes(), &mut key[..])
        .map_err(|_| eyre!("could not derive seed sealing key"))?;
    Ok(key)
}

fn validate_purpose(purpose: &str) -> Result<()> {
    ensure!(
        matches!(
            purpose,
            "package-seed" | "fsverity-seed" | "assoc-seed" | "recovery-seed" | "mint-seed"
        ) && purpose.is_ascii()
            && purpose.len() <= MAX_PURPOSE_LEN,
        "seed purpose is unsupported"
    );
    Ok(())
}
