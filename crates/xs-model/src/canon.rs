//! Canonical JSON (RFC 8785, the JSON Canonicalization Scheme).
//!
//! Record ids, claim ids, the compiled rule pack and the report are all bytes
//! produced here, so two machines that agree on a value agree on its bytes.
//!
//! The writer is deliberately narrower than the RFC: it accepts integers only.
//! Evidence holds no fractional numbers, and number formatting is the one part
//! of the scheme that is hard to get right, so a float is an error rather
//! than a formatting problem. Integers must lie in the range every JSON
//! implementation can represent exactly (±(2^53 − 1)).
//!
//! `serde_json_canonicalizer` is not `no_std`, so it cannot be a dependency
//! here. The tests use it as an oracle instead.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::Serialize;
use serde_json::Value;

/// Largest integer magnitude that survives a round trip through an IEEE 754
/// double, which is what RFC 8785 assumes every number is.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Deepest nesting the writer accepts. The model's own types nest five levels
/// at most; the limit only stops a hostile document from exhausting the stack.
const MAX_DEPTH: usize = 64;

/// Why a value has no canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    /// The value holds a number with a fractional part or an exponent.
    Float,
    /// The value holds an integer outside ±(2^53 − 1).
    IntegerOutOfRange,
    /// The value nests deeper than the writer accepts.
    TooDeep,
    /// The value could not be turned into a JSON tree at all.
    Serialize(String),
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Float => f.write_str("canonical JSON here holds integers only, found a float"),
            Self::IntegerOutOfRange => {
                f.write_str("integer is outside the exactly representable range of ±(2^53 − 1)")
            }
            Self::TooDeep => write!(f, "value nests deeper than {MAX_DEPTH} levels"),
            Self::Serialize(message) => write!(f, "value is not representable as JSON: {message}"),
        }
    }
}

impl core::error::Error for CanonError {}

/// Canonical JSON bytes of any serializable value.
///
/// # Errors
///
/// Fails if the value holds a float, an integer outside ±(2^53 − 1), or nests
/// deeper than 64 levels.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonError> {
    let tree = serde_json::to_value(value).map_err(|e| CanonError::Serialize(e.to_string()))?;
    let mut out = Vec::with_capacity(256);
    write_value(&mut out, &tree, 0)?;
    Ok(out)
}

/// Canonical JSON text of any serializable value.
///
/// # Errors
///
/// Same conditions as [`to_vec`].
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, CanonError> {
    let bytes = to_vec(value)?;
    // The writer only ever emits UTF-8: ASCII structure plus string contents
    // copied from `&str`. The fallback is unreachable and loses nothing.
    Ok(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into()))
}

fn write_value(out: &mut Vec<u8>, value: &Value, depth: usize) -> Result<(), CanonError> {
    if depth > MAX_DEPTH {
        return Err(CanonError::TooDeep);
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_integer(out, number)?,
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            // RFC 8785 section 3.2.3: members are ordered by their names as
            // UTF-16 code units. That differs from byte order for characters
            // outside the Basic Multilingual Plane, so the map's own order
            // (bytes) is not good enough.
            let mut entries: Vec<(&String, &Value)> = members.iter().collect();
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (index, (name, member)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(out, name);
                out.push(b':');
                write_value(out, member, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_integer(out: &mut Vec<u8>, number: &serde_json::Number) -> Result<(), CanonError> {
    if let Some(unsigned) = number.as_u64() {
        if unsigned > MAX_SAFE_INTEGER {
            return Err(CanonError::IntegerOutOfRange);
        }
        out.extend_from_slice(unsigned.to_string().as_bytes());
        Ok(())
    } else if let Some(signed) = number.as_i64() {
        if signed.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonError::IntegerOutOfRange);
        }
        out.extend_from_slice(signed.to_string().as_bytes());
        Ok(())
    } else {
        Err(CanonError::Float)
    }
}

/// Appends `text` as a canonical JSON string.
///
/// RFC 8785 section 3.2.2.2: the two mandatory escapes, the short forms for
/// five control characters, `\u00xx` for the remaining ones, and everything
/// else verbatim. Public so that fixed-shape preimages (such as the bundle
/// digest) can be built without a fallible detour through a JSON tree.
pub fn write_string(out: &mut Vec<u8>, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for byte in text.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0a => out.extend_from_slice(b"\\n"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0d => out.extend_from_slice(b"\\r"),
            0x00..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(byte >> 4)]);
                out.push(HEX[usize::from(byte & 0x0f)]);
            }
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use proptest::prelude::*;
    use serde_json::{Value, json};

    use super::{CanonError, to_string};

    #[test]
    fn sorts_members_and_drops_whitespace() {
        let value = json!({"b": [1, 2, {"z": null, "a": true}], "a": "x"});
        assert_eq!(to_string(&value).unwrap(), r#"{"a":"x","b":[1,2,{"a":true,"z":null}]}"#);
    }

    #[test]
    fn sorts_by_utf16_code_units_not_bytes() {
        // U+1F600 is a surrogate pair starting 0xD83D in UTF-16, which sorts
        // before U+FB33 (0xFB33). In UTF-8 bytes the order is the reverse.
        let value = json!({"\u{fb33}": 1, "\u{1f600}": 2});
        assert_eq!(to_string(&value).unwrap(), "{\"\u{1f600}\":2,\"\u{fb33}\":1}");
    }

    #[test]
    fn escapes_like_rfc_8785() {
        let value = json!("\u{0}\u{8}\t\n\u{c}\r\u{1f}\"\\/\u{7f}\u{2028}é");
        assert_eq!(
            to_string(&value).unwrap(),
            "\"\\u0000\\b\\t\\n\\f\\r\\u001f\\\"\\\\/\u{7f}\u{2028}é\""
        );
    }

    #[test]
    fn rejects_floats_and_unsafe_integers() {
        assert_eq!(to_string(&json!({"x": 1.5})), Err(CanonError::Float));
        assert_eq!(
            to_string(&json!(9_007_199_254_740_992_u64)),
            Err(CanonError::IntegerOutOfRange)
        );
        assert_eq!(
            to_string(&json!(-9_007_199_254_740_992_i64)),
            Err(CanonError::IntegerOutOfRange)
        );
        assert_eq!(to_string(&json!(9_007_199_254_740_991_u64)).unwrap(), "9007199254740991");
        assert_eq!(to_string(&json!(-9_007_199_254_740_991_i64)).unwrap(), "-9007199254740991");
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut value = json!(0);
        for _ in 0..70 {
            value = json!([value]);
        }
        assert_eq!(to_string(&value), Err(CanonError::TooDeep));
    }

    /// Arbitrary JSON trees without floats, with keys and strings drawn from
    /// the whole of Unicode so that escaping and UTF-16 ordering are both hit.
    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::from),
            (-9_007_199_254_740_991_i64..=9_007_199_254_740_991_i64).prop_map(Value::from),
            any::<String>().prop_map(Value::from),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::from),
                prop::collection::vec((any::<String>(), inner), 0..6)
                    .prop_map(|members| Value::Object(members.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// The independent RFC 8785 implementation agrees byte for byte.
        #[test]
        fn agrees_with_the_reference_implementation(value in arb_json()) {
            let ours = to_string(&value).unwrap();
            let reference = serde_json_canonicalizer::to_string(&value).unwrap();
            prop_assert_eq!(ours, reference);
        }

        /// Canonical output parses back to the same tree, and canonicalizing
        /// that tree changes nothing.
        #[test]
        fn is_a_fixed_point(value in arb_json()) {
            let first = to_string(&value).unwrap();
            let parsed: Value = serde_json::from_str(&first).unwrap();
            prop_assert_eq!(&parsed, &value);
            prop_assert_eq!(to_string(&parsed).unwrap(), first);
        }

        /// Member order in the input cannot reach the output.
        #[test]
        fn ignores_insertion_order(members in prop::collection::btree_map(any::<String>(), any::<i32>(), 0..12)) {
            let forward: Vec<(String, Value)> =
                members.iter().map(|(k, v)| (k.clone(), Value::from(*v))).collect();
            let mut backward = forward.clone();
            backward.reverse();
            let a = Value::Object(forward.into_iter().collect());
            let b = Value::Object(backward.into_iter().collect());
            prop_assert_eq!(to_string(&a).unwrap(), to_string(&b).unwrap());
        }
    }
}
