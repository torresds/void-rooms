use std::fmt;

use openmls::prelude::{BasicCredential, CredentialWithKey};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;

use crate::vault::{self, VaultError};

const MAX_IDENTITY_SIZE: usize = 256;

pub struct DeviceIdentity {
    identity: Vec<u8>,
    signer: SignatureKeyPair,
}

impl DeviceIdentity {
    pub fn generate(identity: impl Into<Vec<u8>>, passphrase: &str) -> Result<Self, VaultError> {
        let identity = identity.into();
        if identity.is_empty() || identity.len() > MAX_IDENTITY_SIZE {
            return Err(VaultError::InvalidIdentity);
        }
        vault::validate_passphrase(passphrase)?;
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|_| VaultError::CryptoFailure)?;
        Ok(Self { identity, signer })
    }

    pub fn unlock(vault_bytes: &[u8], passphrase: &str) -> Result<Self, VaultError> {
        vault::open(vault_bytes, passphrase)
    }

    pub fn seal(&self, passphrase: &str) -> Result<Vec<u8>, VaultError> {
        vault::seal(self, passphrase)
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub fn signing_public_key(&self) -> &[u8] {
        self.signer.public()
    }

    pub fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.identity.clone()).into(),
            signature_key: self.signer.to_public_vec().into(),
        }
    }

    pub fn lock(self) {
        drop(self);
    }

    pub(crate) fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    pub(crate) fn from_parts(identity: Vec<u8>, signer: SignatureKeyPair) -> Self {
        Self { identity, signer }
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("identity", &"[REDACTED]")
            .field("signer", &"[REDACTED]")
            .finish()
    }
}
