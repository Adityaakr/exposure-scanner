//! Loading signed rule packs: what is accepted and, above all, what is
//! refused.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use std::io::Cursor;

use xs_model::pack::PackError;
use xs_rules::{
    LoadError, SignedLayer, TRUSTED_KEYS, TrustedKey, load_layer, load_pack, verify_signature,
};

/// The pack and signature committed to the repository, exactly as the
/// scanner embeds them.
const BUILT_IN: &[u8] = include_bytes!("../../../rules/dist/core.pack.json");
const BUILT_IN_SIGNATURE: &str = include_str!("../../../rules/dist/core.pack.json.minisig");

/// A throwaway key pair, as a trusted key and a signing function.
struct TestKey {
    trusted: TrustedKey,
    pair: minisign::KeyPair,
}

impl TestKey {
    fn new() -> Self {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let file = format!("untrusted comment: test key\n{}\n", pair.pk.to_base64());
        Self {
            trusted: TrustedKey { name: "test", minisign: Box::leak(file.into_boxed_str()) },
            pair,
        }
    }

    fn sign(&self, bytes: &[u8]) -> String {
        minisign::sign(None, &self.pair.sk, Cursor::new(bytes), Some("test"), None)
            .unwrap()
            .into_string()
    }
}

#[test]
fn the_built_in_pack_is_signed_by_a_built_in_key() {
    let pack =
        load_pack(&[SignedLayer { bytes: BUILT_IN, signature: BUILT_IN_SIGNATURE }], TRUSTED_KEYS)
            .unwrap();
    assert!(pack.rule_count() >= 10);
    assert_eq!(pack.refs()[0].layer, "core");
    assert_eq!(verify_signature(BUILT_IN, BUILT_IN_SIGNATURE, TRUSTED_KEYS), Ok("exposure-pack-1"));
}

/// Build plan, task 3: a tampered pack is refused.
#[test]
fn a_tampered_pack_is_refused() {
    // Every single-bit change to a sample of positions, plus added and
    // removed bytes. Whatever the change does to the JSON, the signature
    // check comes first and must fail.
    for position in (0..BUILT_IN.len()).step_by(97) {
        let mut tampered = BUILT_IN.to_vec();
        tampered[position] ^= 0x01;
        let result = load_layer(
            SignedLayer { bytes: &tampered, signature: BUILT_IN_SIGNATURE },
            TRUSTED_KEYS,
        );
        assert_eq!(result.unwrap_err(), LoadError::Untrusted, "byte {position}");
    }
    let mut longer = BUILT_IN.to_vec();
    longer.push(b'\n');
    let shorter = &BUILT_IN[..BUILT_IN.len() - 1];
    for tampered in [longer.as_slice(), shorter, b""] {
        let result = load_layer(
            SignedLayer { bytes: tampered, signature: BUILT_IN_SIGNATURE },
            TRUSTED_KEYS,
        );
        assert_eq!(result.unwrap_err(), LoadError::Untrusted);
    }
}

#[test]
fn a_rule_added_to_the_pack_is_refused() {
    // The attack that matters: make the scanner accuse an app, or stay
    // silent about one, by editing a rule.
    let text = std::str::from_utf8(BUILT_IN).unwrap();
    let edited = text.replace("Sentry.framework", "Sparkle.framewor2");
    assert_ne!(edited, text);
    let result = load_layer(
        SignedLayer { bytes: edited.as_bytes(), signature: BUILT_IN_SIGNATURE },
        TRUSTED_KEYS,
    );
    assert_eq!(result.unwrap_err(), LoadError::Untrusted);
}

#[test]
fn a_pack_signed_by_an_unknown_key_is_refused() {
    let stranger = TestKey::new();
    let signature = stranger.sign(BUILT_IN);
    // Valid signature, wrong signer.
    assert!(verify_signature(BUILT_IN, &signature, &[stranger.trusted]).is_ok());
    let result = load_layer(SignedLayer { bytes: BUILT_IN, signature: &signature }, TRUSTED_KEYS);
    assert_eq!(result.unwrap_err(), LoadError::Untrusted);
    // And with no trusted keys at all, nothing loads.
    let result = load_layer(SignedLayer { bytes: BUILT_IN, signature: BUILT_IN_SIGNATURE }, &[]);
    assert_eq!(result.unwrap_err(), LoadError::Untrusted);
}

#[test]
fn a_tampered_signature_file_is_refused() {
    // Swap the trusted comment: the global signature covers it.
    let forged = BUILT_IN_SIGNATURE.replace("version=1", "version=9");
    assert_ne!(forged, BUILT_IN_SIGNATURE);
    assert_eq!(verify_signature(BUILT_IN, &forged, TRUSTED_KEYS), Err(LoadError::Untrusted));

    for garbage in ["", "not a signature", "untrusted comment: x\nAAAA\ntrusted comment: y\nAAAA\n"]
    {
        assert_eq!(
            verify_signature(BUILT_IN, garbage, TRUSTED_KEYS),
            Err(LoadError::BadSignatureFile)
        );
    }
}

#[test]
fn any_one_of_several_trusted_keys_suffices() {
    let other = TestKey::new();
    let mut keys = vec![other.trusted];
    keys.extend_from_slice(TRUSTED_KEYS);
    assert_eq!(verify_signature(BUILT_IN, BUILT_IN_SIGNATURE, &keys), Ok("exposure-pack-1"));
    assert_eq!(verify_signature(BUILT_IN, &other.sign(BUILT_IN), &keys), Ok("test"));
}

#[test]
fn a_broken_built_in_key_is_reported_as_such() {
    let broken = [TrustedKey { name: "broken", minisign: "untrusted comment: x\nnot-base64\n" }];
    assert_eq!(
        verify_signature(BUILT_IN, BUILT_IN_SIGNATURE, &broken),
        Err(LoadError::BadTrustedKey("broken"))
    );
}

/// Even a correctly signed file must be a canonical, valid layer.
#[test]
fn signed_bytes_must_still_be_a_canonical_valid_layer() {
    let key = TestKey::new();
    let keys = [key.trusted];
    let load =
        |bytes: &[u8]| load_pack(&[SignedLayer { bytes, signature: &key.sign(bytes) }], &keys);

    assert!(load(BUILT_IN).is_ok());
    assert!(matches!(load(b"{\"hello\":1}"), Err(LoadError::Parse(_))));
    assert!(matches!(load(b"\xff\xfe"), Err(LoadError::Parse(_))));

    // The same layer with different whitespace is not the canonical form.
    let mut spaced = BUILT_IN.to_vec();
    spaced.push(b' ');
    assert_eq!(load(&spaced).unwrap_err(), LoadError::NotCanonical);

    // An unknown field is refused, not ignored.
    let text = std::str::from_utf8(BUILT_IN).unwrap();
    let extra = text.replacen('{', "{\"aaa\":1,", 1);
    assert!(matches!(load(extra.as_bytes()), Err(LoadError::Parse(_))));

    // A future format version is refused.
    let future = text.replace("\"format\":1", "\"format\":2");
    assert_ne!(future, text);
    assert!(matches!(load(future.as_bytes()), Err(LoadError::Parse(_))));

    // A rule that points at an entity the pack does not define.
    let dangling = text.replace("\"entity\":\"sentry\"", "\"entity\":\"nobody\"");
    assert_ne!(dangling, text);
    assert_eq!(
        load(dangling.as_bytes()).unwrap_err(),
        LoadError::Pack(PackError::Dangling("sdk/sentry".into(), "entity", "nobody".into()))
    );
}

#[test]
fn the_same_layer_twice_is_not_a_pack() {
    let layer = SignedLayer { bytes: BUILT_IN, signature: BUILT_IN_SIGNATURE };
    assert_eq!(
        load_pack(&[layer, layer], TRUSTED_KEYS).unwrap_err(),
        LoadError::Pack(PackError::Duplicate("layer", "core".into()))
    );
    assert_eq!(load_pack(&[], TRUSTED_KEYS).unwrap_err(), LoadError::Pack(PackError::NoLayers));
}
