//! Finding artifacts. Discovery only looks at names and file types; it reads
//! no file content.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ScanError;

/// How far below a folder given on the command line bundles are looked for:
/// the folder's entries and the entries of its sub-folders, which covers
/// `/Applications` and `/Applications/Utilities` (design report, section 4.8).
const MAX_FOLDER_DEPTH: u32 = 2;

fn is_bundle_name(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
}

/// Resolves `paths` to the application bundles they name or contain.
///
/// A path to a bundle yields that bundle. A path to any other folder yields
/// the bundles inside it, down to two levels, without looking inside bundles.
/// Symbolic links to bundles are followed once, and the result is
/// de-duplicated by canonical path, so one bundle reachable two ways is one
/// artifact. The result is sorted; its order affects scheduling only, never
/// output.
///
/// # Errors
///
/// Fails if a given path does not exist, cannot be read, or is neither a
/// bundle nor a folder.
pub fn bundles(paths: &[PathBuf]) -> Result<Vec<PathBuf>, ScanError> {
    let mut found = BTreeSet::new();
    for path in paths {
        let fail = |error| ScanError::Path { path: path.clone(), error };
        let resolved = fs::canonicalize(path).map_err(fail)?;
        if !fs::metadata(&resolved).map_err(fail)?.is_dir() {
            return Err(ScanError::Unsupported(path.clone()));
        }
        // The name the user gave decides, so `Foo.app` given through a link
        // named `Foo.app` is a bundle whatever the link points at is called.
        if is_bundle_name(path) || is_bundle_name(&resolved) {
            found.insert(resolved);
        } else {
            search_folder(&resolved, MAX_FOLDER_DEPTH, &mut found).map_err(fail)?;
        }
    }
    Ok(found.into_iter().collect())
}

/// Adds the bundles inside `folder` to `found`. Sub-folders that cannot be
/// listed are passed over: the user asked for the folder above them, and a
/// locked sub-folder is not a reason to refuse the rest.
fn search_folder(folder: &Path, depth: u32, found: &mut BTreeSet<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(folder)? {
        let path = entry?.path();
        // `metadata` follows a symbolic link, which is the "followed once".
        let Ok(metadata) = fs::metadata(&path) else { continue };
        if !metadata.is_dir() {
            continue;
        }
        if is_bundle_name(&path) {
            if let Ok(resolved) = fs::canonicalize(&path) {
                found.insert(resolved);
            }
        } else if depth > 1 && !fs::symlink_metadata(&path).is_ok_and(|m| m.is_symlink()) {
            // Plain sub-folders only; a link to a folder is not descended into.
            let _ = search_folder(&path, depth - 1, found);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn names(root: &Path, found: &[PathBuf]) -> Vec<String> {
        let root = fs::canonicalize(root).unwrap();
        found.iter().map(|path| path.strip_prefix(&root).unwrap().display().to_string()).collect()
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for path in [
            "Apps/One.app/Contents",
            "Apps/Two.APP/Contents",
            "Apps/Utilities/Three.app/Contents/Frameworks/Helper.app",
            "Apps/Utilities/Deep/Four.app",
            "Apps/NotAnApp",
            "Elsewhere/Five.app",
        ] {
            fs::create_dir_all(dir.path().join(path)).unwrap();
        }
        fs::write(dir.path().join("Apps/file.app"), b"a file, not a bundle").unwrap();
        dir
    }

    #[test]
    fn a_folder_yields_its_bundles_two_levels_down_and_no_further() {
        let dir = tree();
        let found = bundles(&[dir.path().join("Apps")]).unwrap();
        assert_eq!(
            names(dir.path(), &found),
            ["Apps/One.app", "Apps/Two.APP", "Apps/Utilities/Three.app"]
        );
    }

    #[test]
    fn a_bundle_path_yields_that_bundle_and_not_bundles_inside_it() {
        let dir = tree();
        let found = bundles(&[dir.path().join("Apps/Utilities/Three.app")]).unwrap();
        assert_eq!(names(dir.path(), &found), ["Apps/Utilities/Three.app"]);
    }

    #[test]
    fn one_bundle_reached_several_ways_is_one_artifact() {
        let dir = tree();
        symlink(dir.path().join("Elsewhere/Five.app"), dir.path().join("Apps/Link.app")).unwrap();
        symlink(dir.path().join("Apps/One.app"), dir.path().join("Apps/Alias.app")).unwrap();
        let found = bundles(&[
            dir.path().join("Apps"),
            dir.path().join("Apps/One.app"),
            dir.path().join("Apps/./One.app"),
            dir.path().join("Elsewhere"),
        ])
        .unwrap();
        assert_eq!(
            names(dir.path(), &found),
            ["Apps/One.app", "Apps/Two.APP", "Apps/Utilities/Three.app", "Elsewhere/Five.app"]
        );
    }

    #[test]
    fn links_to_plain_folders_are_not_descended_into() {
        let dir = tree();
        symlink(dir.path().join("Elsewhere"), dir.path().join("Apps/Shortcut")).unwrap();
        let found = bundles(&[dir.path().join("Apps")]).unwrap();
        assert!(!names(dir.path(), &found).iter().any(|name| name.contains("Five")));
    }

    #[test]
    fn the_order_of_the_paths_given_does_not_matter() {
        let dir = tree();
        let forward = [dir.path().join("Apps"), dir.path().join("Elsewhere")];
        let backward = [dir.path().join("Elsewhere"), dir.path().join("Apps")];
        assert_eq!(bundles(&forward).unwrap(), bundles(&backward).unwrap());
    }

    #[test]
    fn missing_paths_and_plain_files_are_errors() {
        let dir = tree();
        assert!(matches!(bundles(&[dir.path().join("nope")]), Err(ScanError::Path { .. })));
        assert!(matches!(
            bundles(&[dir.path().join("Apps/file.app")]),
            Err(ScanError::Unsupported(_))
        ));
        assert!(bundles(&[dir.path().join("Apps/NotAnApp")]).unwrap().is_empty());
    }
}
