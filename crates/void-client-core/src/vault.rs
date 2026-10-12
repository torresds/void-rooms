use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls_basic_credential::SignatureKeyPair;
use zeroize::Zeroizing;

use crate::DeviceIdentity;

const MAGIC: &[u8; 4] = b"VRT5";
const VERSION: u16 = 1;
const MEMORY_KIB: u32 = 19_456;
const ITERATIONS: u32 = 2;
const LANES: u32 = 1;
const KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const HEADER_SIZE: usize = 4 + 2 + 4 + 4 + 4 + SALT_SIZE + NONCE_SIZE;
const MAX_PASSPHRASE_SIZE: usize = 1024;
const MAX_PLAINTEXT_SIZE: usize = 4096;
const MAX_SIGNER_SIZE: usize = 1024;
pub const MAX_VAULT_SIZE: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultError {
    InvalidIdentity,
    InvalidPassphrase,
    InvalidSecret,
    CorruptVault,
    UnsupportedVersion,
    CryptoFailure,
    RandomFailure,
    VaultTooLarge,
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentity => "invalid device identity",
            Self::InvalidPassphrase => "invalid passphrase",
            Self::InvalidSecret => "vault authentication failed",
            Self::CorruptVault => "corrupt vault",
            Self::UnsupportedVersion => "unsupported vault version or parameters",
            Self::CryptoFailure => "cryptographic operation failed",
            Self::RandomFailure => "secure random generation failed",
            Self::VaultTooLarge => "vault exceeds the supported size",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for VaultError {}

pub(crate) fn validate_passphrase(passphrase: &str) -> Result<(), VaultError> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_SIZE {
        return Err(VaultError::InvalidPassphrase);
    }
    Ok(())
}

pub(crate) fn seal(identity: &DeviceIdentity, passphrase: &str) -> Result<Vec<u8>, VaultError> {
    validate_passphrase(passphrase)?;
    let plaintext = Zeroizing::new(serialize_identity(identity)?);
    let mut salt = [0; SALT_SIZE];
    let mut nonce = [0; NONCE_SIZE];
    getrandom::getrandom(&mut salt).map_err(|_| VaultError::RandomFailure)?;
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::RandomFailure)?;

    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_be_bytes());
    header.extend_from_slice(&MEMORY_KIB.to_be_bytes());
    header.extend_from_slice(&ITERATIONS.to_be_bytes());
    header.extend_from_slice(&LANES.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| VaultError::CryptoFailure)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| VaultError::CryptoFailure)?;
    if header.len() + ciphertext.len() > MAX_VAULT_SIZE {
        return Err(VaultError::VaultTooLarge);
    }
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

pub(crate) fn open(vault: &[u8], passphrase: &str) -> Result<DeviceIdentity, VaultError> {
    validate_passphrase(passphrase)?;
    if vault.len() > MAX_VAULT_SIZE || vault.len() < HEADER_SIZE + TAG_SIZE {
        return Err(VaultError::CorruptVault);
    }
    if &vault[..4] != MAGIC {
        return Err(VaultError::CorruptVault);
    }
    let version = u16::from_be_bytes([vault[4], vault[5]]);
    if version != VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let memory_kib = u32::from_be_bytes(vault[6..10].try_into().expect("fixed header"));
    let iterations = u32::from_be_bytes(vault[10..14].try_into().expect("fixed header"));
    let lanes = u32::from_be_bytes(vault[14..18].try_into().expect("fixed header"));
    if (memory_kib, iterations, lanes) != (MEMORY_KIB, ITERATIONS, LANES) {
        return Err(VaultError::UnsupportedVersion);
    }

    let salt: &[u8; SALT_SIZE] = vault[18..34].try_into().expect("fixed header");
    let nonce: &[u8; NONCE_SIZE] = vault[34..46].try_into().expect("fixed header");
    let key = derive_key(passphrase, salt)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| VaultError::CryptoFailure)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &vault[HEADER_SIZE..],
                aad: &vault[..HEADER_SIZE],
            },
        )
        .map_err(|_| VaultError::InvalidSecret)?;
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(VaultError::CorruptVault);
    }
    deserialize_identity(&plaintext)
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_SIZE],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, VaultError> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(KEY_SIZE))
        .map_err(|_| VaultError::CryptoFailure)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; KEY_SIZE]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| VaultError::CryptoFailure)?;
    Ok(key)
}

fn serialize_identity(identity: &DeviceIdentity) -> Result<Vec<u8>, VaultError> {
    let signer = Zeroizing::new(
        identity
            .signer()
            .tls_serialize_detached()
            .map_err(|_| VaultError::CryptoFailure)?,
    );
    if signer.len() > MAX_SIGNER_SIZE {
        return Err(VaultError::VaultTooLarge);
    }
    let mut plaintext = Vec::with_capacity(4 + identity.identity().len() + signer.len());
    plaintext.extend_from_slice(&(identity.identity().len() as u16).to_be_bytes());
    plaintext.extend_from_slice(identity.identity());
    plaintext.extend_from_slice(&(signer.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(signer.as_slice());
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(VaultError::VaultTooLarge);
    }
    Ok(plaintext)
}

fn deserialize_identity(plaintext: &[u8]) -> Result<DeviceIdentity, VaultError> {
    if plaintext.len() < 4 {
        return Err(VaultError::CorruptVault);
    }
    let identity_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    let identity_end = 2usize
        .checked_add(identity_len)
        .filter(|end| *end + 2 <= plaintext.len())
        .ok_or(VaultError::CorruptVault)?;
    if identity_len == 0 || identity_len > 256 {
        return Err(VaultError::CorruptVault);
    }
    let signer_len =
        u16::from_be_bytes([plaintext[identity_end], plaintext[identity_end + 1]]) as usize;
    if signer_len == 0 || signer_len > MAX_SIGNER_SIZE {
        return Err(VaultError::CorruptVault);
    }
    let signer_start = identity_end + 2;
    let signer_end = signer_start
        .checked_add(signer_len)
        .filter(|end| *end == plaintext.len())
        .ok_or(VaultError::CorruptVault)?;
    let signer = SignatureKeyPair::tls_deserialize_exact(&plaintext[signer_start..signer_end])
        .map_err(|_| VaultError::CorruptVault)?;
    if signer.signature_scheme() != openmls_traits::types::SignatureScheme::ED25519
        || signer.public().len() != 32
    {
        return Err(VaultError::CorruptVault);
    }
    Ok(DeviceIdentity::from_parts(
        plaintext[2..identity_end].to_vec(),
        signer,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn identity_and_signing_key_survive_seal_and_unlock() {
        let identity = DeviceIdentity::generate(b"device-local".to_vec(), PASSPHRASE)
            .expect("generate identity");
        let public_key = identity.signing_public_key().to_vec();
        let vault = identity.seal(PASSPHRASE).expect("seal identity");
        let restored = DeviceIdentity::unlock(&vault, PASSPHRASE).expect("unlock identity");

        assert_eq!(restored.identity(), b"device-local");
        assert_eq!(restored.signing_public_key(), public_key);
        assert!(
            !restored
                .credential()
                .credential
                .serialized_content()
                .is_empty()
        );
        assert!(
            !vault
                .windows(PASSPHRASE.len())
                .any(|part| part == PASSPHRASE.as_bytes())
        );
        assert!(
            !vault
                .windows(b"device-local".len())
                .any(|part| part == b"device-local")
        );
    }

    #[test]
    fn wrong_passphrase_and_authenticated_modifications_are_rejected() {
        let identity = DeviceIdentity::generate(b"device-local".to_vec(), PASSPHRASE)
            .expect("generate identity");
        let vault = identity.seal(PASSPHRASE).expect("seal identity");
        assert_eq!(
            DeviceIdentity::unlock(&vault, "wrong passphrase").unwrap_err(),
            VaultError::InvalidSecret
        );

        let mut modified = vault;
        let last = modified.len() - 1;
        modified[last] ^= 1;
        assert_eq!(
            DeviceIdentity::unlock(&modified, PASSPHRASE).unwrap_err(),
            VaultError::InvalidSecret
        );
    }

    #[test]
    fn malformed_lengths_and_unsupported_parameters_are_rejected_before_kdf() {
        assert_eq!(
            DeviceIdentity::unlock(&[0; MAX_VAULT_SIZE + 1], PASSPHRASE).unwrap_err(),
            VaultError::CorruptVault
        );
        assert_eq!(
            DeviceIdentity::unlock(b"short", PASSPHRASE).unwrap_err(),
            VaultError::CorruptVault
        );

        let identity = DeviceIdentity::generate(b"device-local".to_vec(), PASSPHRASE)
            .expect("generate identity");
        let mut vault = identity.seal(PASSPHRASE).expect("seal identity");
        vault[6] ^= 1;
        assert_eq!(
            DeviceIdentity::unlock(&vault, PASSPHRASE).unwrap_err(),
            VaultError::UnsupportedVersion
        );
        vault[6] ^= 1;
        vault[0] = 0;
        assert_eq!(
            DeviceIdentity::unlock(&vault, PASSPHRASE).unwrap_err(),
            VaultError::CorruptVault
        );
    }

    #[test]
    fn malformed_decrypted_payload_lengths_are_rejected() {
        assert_eq!(
            deserialize_identity(&[]).unwrap_err(),
            VaultError::CorruptVault
        );
        assert_eq!(
            deserialize_identity(&[0xff, 0xff, 0, 0]).unwrap_err(),
            VaultError::CorruptVault
        );
        assert_eq!(
            deserialize_identity(&[0, 1, b'a', 0, 0]).unwrap_err(),
            VaultError::CorruptVault
        );
        assert_eq!(
            deserialize_identity(&[0, 1, b'a', 0, 1, 0]).unwrap_err(),
            VaultError::CorruptVault
        );
    }

    #[test]
    fn debug_and_errors_do_not_disclose_identity_or_passphrase() {
        let identity = DeviceIdentity::generate(b"secret-device-name".to_vec(), PASSPHRASE)
            .expect("generate identity");
        let debug = format!("{identity:?}");
        assert!(!debug.contains("secret-device-name"));
        assert!(!debug.contains(PASSPHRASE));
        assert!(!VaultError::InvalidSecret.to_string().contains(PASSPHRASE));
    }

    #[test]
    fn empty_and_oversized_passphrases_are_rejected() {
        assert_eq!(
            DeviceIdentity::generate(b"device-local".to_vec(), "").unwrap_err(),
            VaultError::InvalidPassphrase
        );
        assert_eq!(
            DeviceIdentity::generate(
                b"device-local".to_vec(),
                &"p".repeat(MAX_PASSPHRASE_SIZE + 1)
            )
            .unwrap_err(),
            VaultError::InvalidPassphrase
        );
    }
}
