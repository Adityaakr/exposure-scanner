//! Finding artifacts. Discovery only looks at names and file types; it reads
//! no file content.
//!
//! Three kinds of artifact are found: macOS application bundles, which are
//! folders named `.app`; Android packages, which are files named `.apk`; and
//! browser extensions, which are files named `.xpi` (Firefox) or folders
//! `<id>/<version>` that hold a `manifest.json` (the Chromium family). They
//! are found either below the paths a scan is given ([`artifacts`]) or, when
//! it is given none, where macOS keeps installed apps and the browsers keep
//! their profiles ([`installed`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use xs_model::record::{Browser, CoverageReason};

use crate::ScanError;
use crate::browser::{self, Extension, Form};

/// How far below a folder artifacts are looked for: the folder's entries and
/// the entries of its sub-folders, which covers `/Applications` and
/// `/Applications/Utilities` (design report, section 4.8).
const MAX_FOLDER_DEPTH: u32 = 2;

/// The folder macOS installs apps into for every user of the machine.
const SHARED_APPS: &str = "/Applications";
/// The folder, below a user's home folder, for apps of that user alone.
const USER_APPS: &str = "Applications";
/// The folder of Apple's own apps, on the sealed system volume.
const SYSTEM_APPS: &str = "/System/Applications";

/// Where a scan looked for apps, and where it deliberately did not.
///
/// Its text is the same on every machine and for every user: the fixed
/// folders are named, the user's own as `~/Applications` whether or not it
/// exists, and a path the user gave never is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanScope {
    /// No path was given: the installed-app folders and the profile folders
    /// of the browsers were searched, and `/System/Applications` was not.
    Installed,
    /// Paths were given: what they name was scanned and nothing else. The
    /// installed-app folders were not searched.
    Given,
}

impl fmt::Display for ScanScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Installed => write!(
                f,
                "the apps installed in {SHARED_APPS} and ~/{USER_APPS}; {SYSTEM_APPS} (Apple's \
                 own apps on the sealed system volume) was not searched: name the folder to \
                 scan it; the extensions installed in your profiles of {}",
                browser_names()
            ),
            Self::Given => f.write_str(
                "the paths given and nothing else; the installed-app folders were not searched",
            ),
        }
    }
}

/// The browsers whose profiles are searched, as a reader knows them:
/// `Arc, Brave, … and Vivaldi`.
fn browser_names() -> String {
    let names = Browser::ALL.map(Browser::name);
    match names.split_last() {
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    }
}

fn named(path: &Path, extension: &str) -> bool {
    path.extension().is_some_and(|found| found.eq_ignore_ascii_case(extension))
}

fn is_bundle_name(path: &Path) -> bool {
    named(path, "app")
}

fn is_package_name(path: &Path) -> bool {
    named(path, "apk")
}

/// The artifacts a scan covers, by kind. Each list holds canonical paths, is
/// sorted and names an artifact once, however many ways led to it; its order
/// affects scheduling only, never output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Artifacts {
    /// macOS application bundles: folders named `.app`.
    pub bundles: Vec<PathBuf>,
    /// Android packages: regular files named `.apk`.
    pub packages: Vec<PathBuf>,
    /// Browser extensions: version folders of the Chromium family and
    /// Firefox archives named `.xpi`.
    pub extensions: Vec<Extension>,
    /// How many profile folders of each browser could not be listed while
    /// its extensions were looked for, by the reason. Only a search of the
    /// browsers' own folders fills it.
    pub unlisted: BTreeMap<(Browser, CoverageReason), u32>,
}

/// What a search has found so far.
#[derive(Default)]
struct Found {
    bundles: BTreeSet<PathBuf>,
    packages: BTreeSet<PathBuf>,
    extensions: BTreeSet<Extension>,
}

impl Found {
    fn finish(self) -> Artifacts {
        Artifacts {
            bundles: self.bundles.into_iter().collect(),
            packages: self.packages.into_iter().collect(),
            extensions: self.extensions.into_iter().collect(),
            unlisted: BTreeMap::new(),
        }
    }

    /// Adds the extension at the canonical path `path`, found by path and
    /// so in no browser's profile.
    fn extension(&mut self, path: PathBuf, form: Form) {
        self.extensions.insert(Extension { path, form, browser: None });
    }
}

/// Resolves `paths` to the artifacts they name or contain.
///
/// A path to a bundle yields that bundle, and a path to a file named `.apk`
/// that package. A path to a file named `.xpi` yields that Firefox add-on,
/// and a path to an installed version of a Chromium extension, a folder
/// `<id>/<version>` that holds a `manifest.json`, that extension. A path to
/// any other folder yields the bundles, the packages and the extensions
/// inside it, down to two levels, without looking inside bundles.
/// For a path given here the name the user gave decides, so `Foo.app` given
/// through a link named `Foo.app` is a bundle whatever the link points at is
/// called. Inside a folder, a symbolic link to a bundle is followed once; a
/// link to a package is followed once if what it points at is named `.apk`
/// too, so that a link cannot pass any file of the machine off as an app.
///
/// # Errors
///
/// Fails if a given path does not exist, cannot be read, or is neither an
/// artifact nor a folder.
pub fn artifacts(paths: &[PathBuf]) -> Result<Artifacts, ScanError> {
    let mut found = Found::default();
    for path in paths {
        let fail = |error| ScanError::Path { path: path.clone(), error };
        let resolved = fs::canonicalize(path).map_err(fail)?;
        let metadata = fs::metadata(&resolved).map_err(fail)?;
        let is_named = |test: fn(&Path) -> bool| test(path) || test(&resolved);
        if metadata.is_file() && is_named(is_package_name) {
            found.packages.insert(resolved);
        } else if metadata.is_file() && is_named(browser::is_archive_name) {
            found.extension(resolved, Form::Archive);
        } else if !metadata.is_dir() {
            return Err(ScanError::Unsupported(path.clone()));
        } else if is_named(is_bundle_name) {
            found.bundles.insert(resolved);
        } else if browser::is_version_folder(&resolved) {
            found.extension(resolved, Form::Folder);
        } else {
            search_folder(&resolved, MAX_FOLDER_DEPTH, &mut found).map_err(fail)?;
        }
    }
    Ok(found.finish())
}

/// The folders macOS keeps installed apps in: the one shared by every user,
/// and the one of the user whose home folder is `home`.
#[must_use]
pub fn installed_roots(home: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from(SHARED_APPS)];
    roots.extend(home.map(|home| home.join(USER_APPS)));
    roots
}

/// The apps and the browser extensions installed on this machine: what a
/// scan covers when it is given no path.
///
/// The apps are the artifacts in `/Applications` and in the `Applications`
/// folder of the user who runs the scan, each searched as [`artifacts`]
/// searches a folder. The extensions are those in that user's profiles of
/// the browsers this build knows the folders of; see [`browser::installed`].
/// A browser whose folders cannot be listed does not fail the search: it
/// is counted in [`Artifacts::unlisted`]. Apple's own apps on the sealed system volume, in
/// `/System/Applications`, are not among them; that folder is scanned when
/// it is named. No record says so, since a record needs an app as its
/// subject: the scan says it in its scope, [`ScanScope::Installed`].
///
/// # Errors
///
/// Fails on a system other than macOS, where this build does not know where
/// apps are installed, and if a folder that exists cannot be listed.
pub fn installed() -> Result<Artifacts, ScanError> {
    if !cfg!(target_os = "macos") {
        return Err(ScanError::NoInstalledApps);
    }
    // Whose apps are scanned depends on who runs the scan. Nothing else does:
    // no record holds the folder an app was found in.
    let home = std::env::home_dir();
    let mut found = in_roots(&installed_roots(home.as_deref()))?;
    if let Some(home) = home {
        let browsers = browser::installed(&browser::application_support(&home));
        found.extensions = browsers.extensions;
        found.unlisted = browsers.unlisted;
    }
    Ok(found)
}

/// The artifacts in `roots`, each searched as a folder. A root that does not
/// exist holds nothing: most users have no `Applications` folder of their
/// own.
fn in_roots(roots: &[PathBuf]) -> Result<Artifacts, ScanError> {
    let mut found = Found::default();
    for root in roots {
        let fail = |error| ScanError::Path { path: root.clone(), error };
        match fs::canonicalize(root) {
            Ok(resolved) => {
                search_folder(&resolved, MAX_FOLDER_DEPTH, &mut found).map_err(fail)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(fail(error)),
        }
    }
    Ok(found.finish())
}

/// Adds the artifacts inside `folder` to `found`. Sub-folders that cannot be
/// listed are passed over: the user asked for the folder above them, and a
/// locked sub-folder is not a reason to refuse the rest.
fn search_folder(folder: &Path, depth: u32, found: &mut Found) -> io::Result<()> {
    for entry in fs::read_dir(folder)? {
        let path = entry?.path();
        // `metadata` follows a symbolic link, which is the "followed once".
        let Ok(metadata) = fs::metadata(&path) else { continue };
        let linked = || fs::symlink_metadata(&path).is_ok_and(|entry| entry.is_symlink());
        if metadata.is_file() {
            if is_package_name(&path)
                && let Ok(resolved) = fs::canonicalize(&path)
                && is_package_name(&resolved)
            {
                found.packages.insert(resolved);
            } else if browser::is_archive_name(&path)
                && let Ok(resolved) = fs::canonicalize(&path)
                && browser::is_archive_name(&resolved)
            {
                // As for a package: a link is an add-on only if what it
                // points at is named like one.
                found.extension(resolved, Form::Archive);
            }
        } else if !metadata.is_dir() {
            // A socket, a pipe or a device node.
        } else if is_bundle_name(&path) {
            if let Ok(resolved) = fs::canonicalize(&path) {
                found.bundles.insert(resolved);
            }
        } else if browser::is_version_folder(&path) {
            // A link to a folder is not an extension, as it is not a folder
            // to descend into.
            if !linked()
                && let Ok(resolved) = fs::canonicalize(&path)
                && browser::is_version_folder(&resolved)
            {
                found.extension(resolved, Form::Folder);
            }
        } else if depth > 1 && !linked() {
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

    /// The bundles `paths` name or contain.
    fn bundles(paths: &[PathBuf]) -> Result<Vec<PathBuf>, ScanError> {
        artifacts(paths).map(|found| found.bundles)
    }

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

    /// A tree with packages next to bundles.
    fn package_tree() -> tempfile::TempDir {
        let dir = tree();
        for path in [
            "Apps/one.apk",
            "Apps/Two.APK",
            "Apps/Utilities/three.apk",
            "Apps/Utilities/Deep/four.apk",
            "Apps/One.app/Contents/inside-a-bundle.apk",
            "Apps/notes.txt",
            "Elsewhere/five.apk",
        ] {
            fs::write(dir.path().join(path), b"a file").unwrap();
        }
        fs::create_dir_all(dir.path().join("Apps/folder.apk")).unwrap();
        dir
    }

    /// A folder is searched for packages as it is for bundles: two levels
    /// down, and never inside a bundle.
    #[test]
    fn a_folder_yields_its_packages_two_levels_down_next_to_its_bundles() {
        let dir = package_tree();
        let found = artifacts(&[dir.path().join("Apps")]).unwrap();
        assert_eq!(
            names(dir.path(), &found.packages),
            ["Apps/Two.APK", "Apps/Utilities/three.apk", "Apps/one.apk"]
        );
        assert_eq!(found.bundles, bundles(&[dir.path().join("Apps")]).unwrap());
        assert_eq!(found.bundles.len(), 3);

        let found = artifacts(&[dir.path().join("Apps/Utilities")]).unwrap();
        assert_eq!(
            names(dir.path(), &found.packages),
            ["Apps/Utilities/Deep/four.apk", "Apps/Utilities/three.apk"]
        );
    }

    /// Inside a folder, a link is a package only if what it points at is
    /// named like one: a link must not pass any file off as an app, whose
    /// hash a report would then hold.
    #[test]
    fn a_link_found_in_a_folder_is_a_package_only_if_its_target_is_named_like_one() {
        let dir = package_tree();
        let apps = dir.path().join("Apps");
        symlink(dir.path().join("Elsewhere/five.apk"), apps.join("link.apk")).unwrap();
        symlink(apps.join("notes.txt"), apps.join("renamed.apk")).unwrap();
        symlink(apps.join("one.apk"), apps.join("again.apk")).unwrap();
        symlink(apps.join("gone.apk"), apps.join("dangling.apk")).unwrap();
        let found = artifacts(&[apps]).unwrap();
        assert_eq!(
            names(dir.path(), &found.packages),
            ["Apps/Two.APK", "Apps/Utilities/three.apk", "Apps/one.apk", "Elsewhere/five.apk"]
        );
    }

    #[test]
    fn a_package_path_yields_that_package_and_a_bundle_path_no_packages() {
        let dir = package_tree();
        for package in ["Apps/Utilities/Deep/four.apk", "Apps/Two.APK"] {
            let found = artifacts(&[dir.path().join(package)]).unwrap();
            assert_eq!(names(dir.path(), &found.packages), [package]);
            assert!(found.bundles.is_empty());
        }

        let found = artifacts(&[dir.path().join("Apps/One.app")]).unwrap();
        assert!(found.packages.is_empty());
        assert_eq!(names(dir.path(), &found.bundles), ["Apps/One.app"]);
    }

    #[test]
    fn one_package_reached_several_ways_is_one_artifact() {
        let dir = package_tree();
        symlink(dir.path().join("Elsewhere/five.apk"), dir.path().join("Apps/link.apk")).unwrap();
        // A link whose own name says package decides, whatever it points at.
        symlink(dir.path().join("Apps/notes.txt"), dir.path().join("Apps/renamed.apk")).unwrap();
        let found = artifacts(&[
            dir.path().join("Apps/one.apk"),
            dir.path().join("Apps/./one.apk"),
            dir.path().join("Apps/link.apk"),
            dir.path().join("Elsewhere/five.apk"),
            dir.path().join("Apps/renamed.apk"),
        ])
        .unwrap();
        assert_eq!(
            names(dir.path(), &found.packages),
            ["Apps/notes.txt", "Apps/one.apk", "Elsewhere/five.apk"]
        );
    }

    #[test]
    fn the_order_of_the_paths_given_does_not_matter_for_packages_either() {
        let dir = package_tree();
        let paths =
            ["Apps", "Elsewhere/five.apk", "Apps/one.apk"].map(|path| dir.path().join(path));
        let mut backward = paths.clone();
        backward.reverse();
        let found = artifacts(&paths).unwrap();
        assert_eq!(found, artifacts(&backward).unwrap());
        assert_eq!(
            names(dir.path(), &found.packages),
            ["Apps/Two.APK", "Apps/Utilities/three.apk", "Apps/one.apk", "Elsewhere/five.apk"]
        );
    }

    #[test]
    fn what_is_neither_an_artifact_nor_a_folder_is_still_an_error() {
        let dir = package_tree();
        assert!(matches!(artifacts(&[dir.path().join("nope.apk")]), Err(ScanError::Path { .. })));
        assert!(matches!(
            artifacts(&[dir.path().join("Apps/notes.txt")]),
            Err(ScanError::Unsupported(_))
        ));
        // A folder that happens to be named like a package is a folder.
        let found = artifacts(&[dir.path().join("Apps/folder.apk")]).unwrap();
        assert_eq!(found, Artifacts::default());
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

    /// What a scan covers when it is given no path: both folders macOS keeps
    /// apps in, searched like any folder. A user without a folder of their
    /// own is the usual case, not a failure.
    #[test]
    fn installed_apps_are_those_of_the_shared_folder_and_of_the_user_s_own() {
        assert_eq!(
            installed_roots(Some(Path::new("/Users/someone"))),
            [PathBuf::from("/Applications"), PathBuf::from("/Users/someone/Applications")]
        );
        assert_eq!(installed_roots(None), [PathBuf::from("/Applications")]);

        let dir = package_tree();
        let roots = [dir.path().join("Apps"), dir.path().join("Elsewhere")];
        let found = in_roots(&roots).unwrap();
        assert_eq!(found, artifacts(&roots).unwrap());
        assert_eq!(found.bundles.len(), 4);

        let without = [dir.path().join("Apps"), dir.path().join("nobody/Applications")];
        assert_eq!(in_roots(&without).unwrap(), artifacts(&without[..1]).unwrap());
        assert_eq!(in_roots(&without[1..]).unwrap(), Artifacts::default());
        // A root that is there and is not a folder is not passed over.
        let file = [dir.path().join("Apps/notes.txt")];
        assert!(matches!(in_roots(&file), Err(ScanError::Path { .. })));
    }

    /// What a scan without a path says it covered (design report, section
    /// 4.8, as amended in the README): both installed-app folders, and that
    /// Apple's apps were left out with the way to scan them. The text is
    /// fixed, so it cannot hold the home folder of whoever runs the scan.
    #[test]
    fn the_scope_of_a_scan_of_the_installed_apps_names_what_was_left_out() {
        assert_eq!(
            ScanScope::Installed.to_string(),
            "the apps installed in /Applications and ~/Applications; /System/Applications \
             (Apple's own apps on the sealed system volume) was not searched: name the folder \
             to scan it; the extensions installed in your profiles of Arc, Brave, Google \
             Chrome, Chromium, Dia, Microsoft Edge, Firefox and Vivaldi"
        );
        let given = ScanScope::Given.to_string();
        assert!(given.contains("installed-app folders were not searched"), "{given}");
        assert!(!given.contains("/Applications"), "{given}");
    }

    /// Discovery reads no file, so asking for the installed apps of the
    /// machine the tests run on is cheap.
    #[test]
    fn installed_apps_are_only_known_of_on_macos() {
        let found = installed();
        assert_eq!(found.is_ok(), cfg!(target_os = "macos"), "{found:?}");
        if let Err(error) = found {
            assert!(matches!(error, ScanError::NoInstalledApps), "{error}");
        }
    }
}
