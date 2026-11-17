//! Paths inside an artifact.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use crate::serde_str::impl_serde_str;
use crate::text;

/// Longest artifact-relative path a record carries, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// A path relative to the root of an artifact, such as `classes2.dex` or
/// `Contents/Frameworks`.
///
/// This is the only path type a record can hold, and it cannot express an
/// absolute path or one that climbs out of the artifact. So a record cannot
/// name a location in the user's home folder, which the evidence format
/// forbids, and a report cannot differ between two machines because of where
/// an app happened to be installed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(String);

/// Why a string is not an artifact-relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelPathError {
    /// The path is empty.
    Empty,
    /// The path is longer than [`MAX_PATH_BYTES`].
    TooLong,
    /// The path starts with `/`.
    Absolute,
    /// A component is empty, `.` or `..`.
    BadComponent,
    /// The path holds a control or bidirectional-control character.
    Unprintable,
}

impl fmt::Display for RelPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "path is empty",
            Self::TooLong => "path is longer than 4096 bytes",
            Self::Absolute => "path is absolute; records hold paths inside the artifact only",
            Self::BadComponent => "path has an empty, \".\" or \"..\" component",
            Self::Unprintable => "path holds a control character",
        })
    }
}

impl core::error::Error for RelPathError {}

impl RelPath {
    /// Validates a `/`-separated path relative to the artifact root.
    ///
    /// # Errors
    ///
    /// Fails if the path is empty, absolute, too long, holds a control
    /// character, or has an empty, `.` or `..` component.
    pub fn new(path: &str) -> Result<Self, RelPathError> {
        if path.is_empty() {
            return Err(RelPathError::Empty);
        }
        if path.len() > MAX_PATH_BYTES {
            return Err(RelPathError::TooLong);
        }
        if path.starts_with('/') {
            return Err(RelPathError::Absolute);
        }
        if !path.chars().all(text::is_storable) {
            return Err(RelPathError::Unprintable);
        }
        if path.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
            return Err(RelPathError::BadComponent);
        }
        Ok(Self(String::from(path)))
    }

    /// The path below this one named `component`.
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as [`RelPath::new`]; in particular a
    /// component that contains `/` is rejected only if it creates a bad
    /// component.
    pub fn join(&self, component: &str) -> Result<Self, RelPathError> {
        let mut joined = String::with_capacity(self.0.len() + 1 + component.len());
        joined.push_str(&self.0);
        joined.push('/');
        joined.push_str(component);
        Self::new(&joined)
    }

    /// The path as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RelPath {
    type Err = RelPathError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl_serde_str!(RelPath, "a path relative to the artifact root");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_paths_inside_the_artifact() {
        for path in ["classes2.dex", "Contents/Frameworks", "a/b c/d.e", "lib/arm64-v8a/libx.so"] {
            assert_eq!(RelPath::new(path).unwrap().as_str(), path);
        }
    }

    #[test]
    fn rejects_paths_that_leave_the_artifact() {
        assert_eq!(RelPath::new(""), Err(RelPathError::Empty));
        assert_eq!(RelPath::new("/Users/someone/app"), Err(RelPathError::Absolute));
        for path in ["..", "../x", "a/../b", "a/./b", "a//b", "a/", "."] {
            assert_eq!(RelPath::new(path), Err(RelPathError::BadComponent), "{path}");
        }
        assert_eq!(RelPath::new("a\nb"), Err(RelPathError::Unprintable));
        assert_eq!(RelPath::new(&"a".repeat(MAX_PATH_BYTES + 1)), Err(RelPathError::TooLong));
    }

    #[test]
    fn join_cannot_escape() {
        let base = RelPath::new("Contents").unwrap();
        assert_eq!(base.join("Frameworks").unwrap().as_str(), "Contents/Frameworks");
        assert_eq!(base.join(".."), Err(RelPathError::BadComponent));
        assert_eq!(base.join(""), Err(RelPathError::BadComponent));
    }

    #[test]
    fn deserialization_validates() {
        assert!(serde_json::from_str::<RelPath>("\"a/b\"").is_ok());
        assert!(serde_json::from_str::<RelPath>("\"/etc/passwd\"").is_err());
        assert!(serde_json::from_str::<RelPath>("\"a/../../b\"").is_err());
    }
}
