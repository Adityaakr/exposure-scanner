//! Serde glue for types whose wire form is a single string.

/// Implements `Serialize` through `Display` and `Deserialize` through
/// `FromStr` for a type whose JSON form is one string, such as
/// `"sha256:8aa0…"`. Going through `FromStr` means a value read from a file is
/// validated exactly like one built in code.
macro_rules! impl_serde_str {
    ($ty:ty, $expecting:literal) => {
        impl ::serde::Serialize for $ty {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                struct Visitor;

                impl ::serde::de::Visitor<'_> for Visitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E: ::serde::de::Error>(self, value: &str) -> Result<$ty, E> {
                        value.parse::<$ty>().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }
    };
}

pub(crate) use impl_serde_str;
