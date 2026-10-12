use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, signatures::Signer, types::SignatureScheme};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn credential(
    identity: &[u8],
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("signature key");
    signer.store(provider.storage()).expect("store signer");
    let credential = BasicCredential::new(identity.to_vec());
    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        },
        signer,
    )
}

fn key_package(
    credential: CredentialWithKey,
    signer: &impl Signer,
    provider: &impl OpenMlsProvider,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .build(CIPHERSUITE, provider, signer, credential)
        .expect("build key package")
}

#[test]
fn group_join_authenticated_message_and_provider_reload() {
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = credential(b"alice", &alice_provider);
    let (bob_credential, bob_signer) = credential(b"bob", &bob_provider);
    let bob_key_package = key_package(bob_credential, &bob_signer, &bob_provider);

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build(&alice_provider, &alice_signer, alice_credential)
        .expect("create group");
    let group_id = alice_group.group_id().clone();

    let (_, welcome, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("add member");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("merge add commit");

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let welcome_bytes = welcome.to_bytes().expect("serialize Welcome");
    let welcome =
        MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice()).expect("deserialize Welcome");
    let welcome = match welcome.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected Welcome content"),
    };
    let mut bob_group = StagedWelcome::new_from_welcome(&bob_provider, &join_config, welcome, None)
        .expect("stage welcome")
        .into_group(&bob_provider)
        .expect("join group");

    assert_eq!(alice_group.members().count(), 2);
    assert_eq!(alice_group.group_id(), bob_group.group_id());

    let message = alice_group
        .create_message(&alice_provider, &alice_signer, b"MLS application test")
        .expect("create application message");
    let encoded = message.to_bytes().expect("serialize MLS message");
    let incoming =
        MlsMessageIn::tls_deserialize_exact(encoded.as_slice()).expect("deserialize MLS message");
    let protocol_message = incoming
        .try_into_protocol_message()
        .expect("protocol message");
    let processed = bob_group
        .process_message(&bob_provider, protocol_message)
        .expect("authenticate and process message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message.into_bytes(), b"MLS application test");
        }
        _ => panic!("expected application content"),
    }

    let tampered = alice_group
        .create_message(&alice_provider, &alice_signer, b"tamper check")
        .expect("create tamper test message")
        .to_bytes()
        .expect("serialize tamper test message");
    let mut tampered = tampered;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let incoming = MlsMessageIn::tls_deserialize_exact(tampered.as_slice())
        .expect("tampered frame remains structurally parseable");
    let protocol_message = incoming
        .try_into_protocol_message()
        .expect("tampered protocol message");
    assert!(
        bob_group
            .process_message(&bob_provider, protocol_message)
            .is_err()
    );

    let epoch = alice_group.epoch();
    drop(alice_group);
    let reloaded = MlsGroup::load(alice_provider.storage(), &group_id)
        .expect("read group from provider storage")
        .expect("stored group exists");
    assert_eq!(reloaded.group_id(), &group_id);
    assert_eq!(reloaded.epoch(), epoch);
}
