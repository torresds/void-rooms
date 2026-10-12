#![forbid(unsafe_code)]

use std::collections::HashMap;

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::{OpenMlsProvider, types::SignatureScheme};
use wasm_bindgen::prelude::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const SNAPSHOT_MAGIC: &[u8; 4] = b"VMLS";
const SNAPSHOT_VERSION: u16 = 1;
const MAX_SNAPSHOT_SIZE: usize = 64 * 1024 * 1024;
const MAX_SNAPSHOT_RECORDS: usize = 100_000;

#[derive(Default)]
struct BrowserProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for BrowserProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

struct BrowserClient {
    provider: BrowserProvider,
    signer: SignatureKeyPair,
    signer_public_key: Vec<u8>,
    group: MlsGroup,
}

#[derive(Default)]
#[wasm_bindgen]
pub struct BrowserMlsLab {
    alice: Option<BrowserClient>,
    bob: Option<BrowserClient>,
}

#[wasm_bindgen]
impl BrowserMlsLab {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize(&mut self) -> Result<(), JsValue> {
        if self.alice.is_some() || self.bob.is_some() {
            return Err(js_error("lab is already initialized"));
        }

        let alice_provider = BrowserProvider::default();
        let (alice_credential, alice_signer) = create_credential(&alice_provider, b"alice")?;
        let alice_public_key = alice_signer.to_public_vec();
        let mut alice_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(&alice_provider, &alice_signer, alice_credential)
            .map_err(debug_error)?;

        let bob_provider = BrowserProvider::default();
        let (bob_credential, bob_signer) = create_credential(&bob_provider, b"bob")?;
        let bob_public_key = bob_signer.to_public_vec();
        let bob_key_package = KeyPackage::builder()
            .build(CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
            .map_err(debug_error)?;

        let (_, welcome, _) = alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(bob_key_package.key_package()),
            )
            .map_err(debug_error)?;
        alice_group
            .merge_pending_commit(&alice_provider)
            .map_err(debug_error)?;

        let welcome_bytes = welcome.to_bytes().map_err(debug_error)?;
        let welcome =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice()).map_err(debug_error)?;
        let welcome = match welcome.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(js_error("expected Welcome message")),
        };
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let bob_group = StagedWelcome::new_from_welcome(&bob_provider, &join_config, welcome, None)
            .map_err(debug_error)?
            .into_group(&bob_provider)
            .map_err(debug_error)?;

        self.alice = Some(BrowserClient {
            provider: alice_provider,
            signer: alice_signer,
            signer_public_key: alice_public_key,
            group: alice_group,
        });
        self.bob = Some(BrowserClient {
            provider: bob_provider,
            signer: bob_signer,
            signer_public_key: bob_public_key,
            group: bob_group,
        });
        Ok(())
    }

    pub fn alice_public_key(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.client("alice")?.signer_public_key.clone())
    }

    pub fn bob_public_key(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.client("bob")?.signer_public_key.clone())
    }

    pub fn alice_epoch(&self) -> Result<u64, JsValue> {
        Ok(self.client("alice")?.group.epoch().as_u64())
    }

    pub fn bob_epoch(&self) -> Result<u64, JsValue> {
        Ok(self.client("bob")?.group.epoch().as_u64())
    }

    pub fn snapshot_alice(&self) -> Result<Vec<u8>, JsValue> {
        snapshot(self.client("alice")?)
    }

    pub fn snapshot_bob(&self) -> Result<Vec<u8>, JsValue> {
        snapshot(self.client("bob")?)
    }

    pub fn restore_alice(
        &mut self,
        snapshot_bytes: &[u8],
        expected_public_key: &[u8],
    ) -> Result<(), JsValue> {
        self.alice = Some(restore_client(snapshot_bytes, expected_public_key)?);
        Ok(())
    }

    pub fn restore_bob(
        &mut self,
        snapshot_bytes: &[u8],
        expected_public_key: &[u8],
    ) -> Result<(), JsValue> {
        self.bob = Some(restore_client(snapshot_bytes, expected_public_key)?);
        Ok(())
    }

    pub fn create_alice_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        let client = self.client_mut("alice")?;
        client
            .group
            .create_message(&client.provider, &client.signer, payload)
            .map_err(debug_error)?
            .to_bytes()
            .map_err(debug_error)
    }

    pub fn receive_alice_message(&mut self, encoded: &[u8]) -> Result<Vec<u8>, JsValue> {
        receive_message(self.client_mut("alice")?, encoded)
    }

    pub fn create_bob_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        let client = self.client_mut("bob")?;
        client
            .group
            .create_message(&client.provider, &client.signer, payload)
            .map_err(debug_error)?
            .to_bytes()
            .map_err(debug_error)
    }

    pub fn receive_bob_message(&mut self, encoded: &[u8]) -> Result<Vec<u8>, JsValue> {
        receive_message(self.client_mut("bob")?, encoded)
    }
}

fn create_credential(
    provider: &BrowserProvider,
    identity: &[u8],
) -> Result<(CredentialWithKey, SignatureKeyPair), JsValue> {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(debug_error)?;
    signer.store(provider.storage()).map_err(debug_error)?;
    let credential = BasicCredential::new(identity.to_vec());
    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        },
        signer,
    ))
}

fn receive_message(client: &mut BrowserClient, encoded: &[u8]) -> Result<Vec<u8>, JsValue> {
    let message = MlsMessageIn::tls_deserialize_exact(encoded).map_err(debug_error)?;
    let protocol_message = message.try_into_protocol_message().map_err(debug_error)?;
    let processed = client
        .group
        .process_message(&client.provider, protocol_message)
        .map_err(debug_error)?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
        _ => Err(js_error("expected MLS application message")),
    }
}

fn snapshot(client: &BrowserClient) -> Result<Vec<u8>, JsValue> {
    let records = client
        .provider
        .storage
        .values
        .read()
        .map_err(|_| js_error("provider storage lock poisoned"))?;
    if records.len() > MAX_SNAPSHOT_RECORDS {
        return Err(js_error("too many provider records"));
    }
    let group_id = client.group.group_id().as_slice();
    let public_key = &client.signer_public_key;
    let mut sorted_records: Vec<_> = records.iter().collect();
    sorted_records.sort_by(|left, right| left.0.cmp(right.0));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
    write_len(&mut bytes, group_id.len())?;
    write_len(&mut bytes, public_key.len())?;
    write_len(&mut bytes, sorted_records.len())?;
    bytes.extend_from_slice(group_id);
    bytes.extend_from_slice(public_key);
    for (key, value) in sorted_records {
        write_len(&mut bytes, key.len())?;
        write_len(&mut bytes, value.len())?;
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(value);
        if bytes.len() > MAX_SNAPSHOT_SIZE {
            return Err(js_error("provider snapshot exceeds size limit"));
        }
    }
    Ok(bytes)
}

fn restore_client(bytes: &[u8], expected_public_key: &[u8]) -> Result<BrowserClient, JsValue> {
    if bytes.len() > MAX_SNAPSHOT_SIZE || bytes.len() < 18 {
        return Err(js_error("snapshot size is invalid"));
    }
    let mut cursor = 0;
    if take(bytes, &mut cursor, 4)? != SNAPSHOT_MAGIC {
        return Err(js_error("snapshot magic is invalid"));
    }
    let version = u16::from_be_bytes(take(bytes, &mut cursor, 2)?.try_into().unwrap());
    if version != SNAPSHOT_VERSION {
        return Err(js_error("snapshot version is unsupported"));
    }
    let group_id_len = read_len(bytes, &mut cursor)?;
    let public_key_len = read_len(bytes, &mut cursor)?;
    let record_count = read_len(bytes, &mut cursor)?;
    if group_id_len == 0
        || group_id_len > 256
        || public_key_len != 32
        || record_count > MAX_SNAPSHOT_RECORDS
    {
        return Err(js_error("snapshot metadata is invalid"));
    }
    let group_id_bytes = take(bytes, &mut cursor, group_id_len)?.to_vec();
    let public_key = take(bytes, &mut cursor, public_key_len)?.to_vec();
    if public_key != expected_public_key {
        return Err(js_error("snapshot identity mismatch"));
    }

    let mut records = HashMap::with_capacity(record_count);
    for _ in 0..record_count {
        let key_len = read_len(bytes, &mut cursor)?;
        let value_len = read_len(bytes, &mut cursor)?;
        if key_len > MAX_SNAPSHOT_SIZE || value_len > MAX_SNAPSHOT_SIZE {
            return Err(js_error("snapshot record length is invalid"));
        }
        let key = take(bytes, &mut cursor, key_len)?.to_vec();
        let value = take(bytes, &mut cursor, value_len)?.to_vec();
        if records.insert(key, value).is_some() {
            return Err(js_error("snapshot contains duplicate records"));
        }
    }
    if cursor != bytes.len() {
        return Err(js_error("snapshot has trailing bytes"));
    }

    let provider = BrowserProvider::default();
    {
        let mut storage = provider
            .storage
            .values
            .write()
            .map_err(|_| js_error("provider storage lock poisoned"))?;
        *storage = records;
    }
    let signer = SignatureKeyPair::read(provider.storage(), &public_key, SignatureScheme::ED25519)
        .ok_or_else(|| js_error("signing key is absent from provider storage"))?;
    let group_id = GroupId::from_slice(&group_id_bytes);
    let group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(debug_error)?
        .ok_or_else(|| js_error("group is absent from provider storage"))?;
    Ok(BrowserClient {
        provider,
        signer,
        signer_public_key: public_key,
        group,
    })
}

fn write_len(output: &mut Vec<u8>, len: usize) -> Result<(), JsValue> {
    let len = u32::try_from(len).map_err(debug_error)?;
    output.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn read_len(bytes: &[u8], cursor: &mut usize) -> Result<usize, JsValue> {
    let len = u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().unwrap());
    Ok(len as usize)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], JsValue> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| js_error("snapshot length overflow"))?;
    let part = bytes
        .get(*cursor..end)
        .ok_or_else(|| js_error("snapshot is truncated"))?;
    *cursor = end;
    Ok(part)
}

fn js_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}

fn debug_error(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("MLS operation failed: {error:?}"))
}

impl BrowserMlsLab {
    fn client(&self, role: &str) -> Result<&BrowserClient, JsValue> {
        match role {
            "alice" => self.alice.as_ref(),
            "bob" => self.bob.as_ref(),
            _ => None,
        }
        .ok_or_else(|| js_error("client is unavailable"))
    }

    fn client_mut(&mut self, role: &str) -> Result<&mut BrowserClient, JsValue> {
        match role {
            "alice" => self.alice.as_mut(),
            "bob" => self.bob.as_mut(),
            _ => None,
        }
        .ok_or_else(|| js_error("client is unavailable"))
    }
}
