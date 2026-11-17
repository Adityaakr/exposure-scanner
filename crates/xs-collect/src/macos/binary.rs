//! Reading one Mach-O file: which of its bytes are searched for what.
//!
//! A Mach-O file is read once, in windows, like any other (design report,
//! section 6.2). What sets it apart is that the file itself says where to
//! look. So while the windows go by, [`Binary`] does three things with them:
//!
//! 1. **Structure.** Every fresh byte goes to a
//!    [`Walker`](xs_formats::macho::Walker), which keeps only headers and
//!    load commands and hands back an image per architecture. The image
//!    names the libraries the file links and the byte ranges that matter.
//!    Those ranges always lie ahead of the commands that name them, so each
//!    is known before the pass reaches it.
//! 2. **Tables.** The bytes of an `__objc_classname` section are split into
//!    names, and each name is matched as a value. The code signature goes
//!    to a [`codesign::Reader`], which keeps two small parts of it and, once
//!    it has gone by, says which Team ID it names and which entitlements it
//!    grants.
//! 3. **Free-form bytes.** Two searches run over parts of the file, each
//!    part being a stream of its own to the content engine:
//!
//!    * `macho_token` literals in every run of bytes **outside** the masked
//!      ranges. Masked are the sections that hold instructions, where there
//!      are no strings, and the encrypted part of an encrypted image, which
//!      is ciphertext. A literal cannot span a masked range.
//!    * `content_literal` literals in each embedded-script section, such as
//!      `__BUN,__bun` (design report, M6). The script is the code of
//!      whoever ships the file: app code in the app's own executable, a
//!      dependency's code in a file a dependency ships. The rest of such a
//!      file is the runtime of the script and is not searched.
//!
//! Where the windows fall changes none of this: a part is fed to the engine
//! under the same contract the reader gives a whole file, with the carry and
//! the last window worked out for the part.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use xs_formats::macho::{Image, Names, Span, Walker};
use xs_formats::{FormatError, ReadError, codesign};
use xs_match::{ContentEngine, ContentMatcher as _, HitAcc, Matchers};
use xs_model::record::Scope;
use xs_model::{MatcherKind, access};

use crate::read::Sink;

/// What reading one Mach-O file found, before any of it is judged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct BinaryFindings {
    /// Every hit in the file: class names, library names, literals.
    pub(super) hits: HitAcc,
    /// The Team IDs the signatures of the file's images name. One for a
    /// file whose images agree.
    pub(super) team_ids: BTreeSet<String>,
    /// The entitlements that ask for a permission, in the signature of any
    /// of the file's images, each with the most entries it holds in one.
    pub(super) entitlements: BTreeMap<String, u32>,
    /// How many images the file holds.
    pub(super) images: u32,
    /// How many of them have a signature that asks for the App Sandbox.
    pub(super) sandboxed: u32,
    /// How many of them have a signature that could not be read to the
    /// end, entitlements included. What such an image asks for is not
    /// known.
    pub(super) signatures_unread: u32,
    /// Signatures whose entitlements are in a form this build cannot read.
    pub(super) unsupported: u32,
    /// Whether the file holds an embedded-script section, which makes the
    /// rest of it a language runtime.
    pub(super) has_script: bool,
    /// Images that are encrypted.
    pub(super) encrypted: u32,
    /// Images, parts of images and signatures that are not well formed.
    pub(super) malformed: u32,
    /// Images, name-table entries and signatures over a budget.
    pub(super) over_budget: u32,
}

impl BinaryFindings {
    /// Whether the file's signature asks for the App Sandbox: `Some` when
    /// every image says the same and each signature could be read. An image
    /// with no signature at all asks for nothing.
    pub(super) fn sandbox(&self) -> Option<bool> {
        if self.images == 0 || self.signatures_unread > 0 {
            None
        } else if self.sandboxed == self.images {
            Some(true)
        } else if self.sandboxed == 0 {
            Some(false)
        } else {
            None
        }
    }
}

/// The state of one pass over a Mach-O file.
pub(super) struct Binary<'m, 'p> {
    matchers: &'m Matchers<'p>,
    /// What kind of code the file is, from where it sits in the bundle.
    scope: Scope,
    /// Searches the bytes outside the masked ranges.
    tokens: &'m ContentEngine,
    /// Searches embedded-script sections.
    script: &'m ContentEngine,
    walker: Walker,
    /// File offset of the first fresh byte of the next window.
    offset: u64,

    /// Masked ranges not gone by yet, ascending.
    masks: VecDeque<Span>,
    /// Where the run of unmasked bytes that is being searched starts.
    run_start: u64,
    /// Name tables not gone by yet, ascending, and the one being split.
    name_tables: VecDeque<Span>,
    names: Names,
    /// Script sections not gone by yet, ascending.
    scripts: VecDeque<Span>,
    /// Signatures not gone by yet, ascending, and the reader of the one
    /// going by.
    signatures: VecDeque<Span>,
    signature: codesign::Reader,

    /// Hits of the table matchers, which run on every file.
    table_hits: HitAcc,
    /// Hits outside the masked ranges. Dropped if the file turns out to be
    /// a runtime.
    token_hits: HitAcc,
    script_hits: HitAcc,
    found: BinaryFindings,
}

impl<'m, 'p> Binary<'m, 'p> {
    /// A pass over a file of `scope`.
    pub(super) fn new(matchers: &'m Matchers<'p>, scope: Scope) -> Self {
        Self {
            matchers,
            scope,
            tokens: matchers.content(MatcherKind::MachoToken, scope),
            // A script section is searched as what the file is by where it
            // sits. It is the file around the script that becomes a runtime.
            script: matchers.content(MatcherKind::ContentLiteral, scope),
            walker: Walker::new(),
            offset: 0,
            masks: VecDeque::new(),
            run_start: 0,
            name_tables: VecDeque::new(),
            names: Names::new(),
            scripts: VecDeque::new(),
            signatures: VecDeque::new(),
            signature: codesign::Reader::new(),
            table_hits: HitAcc::new(),
            token_hits: HitAcc::new(),
            script_hits: HitAcc::new(),
            found: BinaryFindings::default(),
        }
    }

    /// Takes in what the load commands of one image say.
    fn admit(&mut self, image: Image) {
        for library in &image.libraries {
            match_library(self.matchers, self.scope, library, &mut self.table_hits);
        }
        self.found.images = self.found.images.saturating_add(1);
        self.found.has_script |= !image.scripts.is_empty();
        self.found.encrypted = self.found.encrypted.saturating_add(u32::from(image.encrypted));
        self.found.malformed = self.found.malformed.saturating_add(image.damaged);
        // Images come in file order and their ranges lie inside them, so
        // each list stays ascending.
        if !self.tokens.is_empty() {
            self.masks.extend(image.masked);
        }
        self.name_tables.extend(image.class_names);
        self.scripts.extend(image.scripts);
        self.signatures.extend(image.signature);
    }

    /// Splits the fresh bytes that lie in a name table into names and
    /// matches each one.
    fn read_names(&mut self, fresh: &[u8], fresh_start: u64, last: bool) {
        let (matchers, scope) = (self.matchers, self.scope);
        let (names, hits, found) = (&mut self.names, &mut self.table_hits, &mut self.found);
        each_part(&mut self.name_tables, fresh, fresh_start, last, |part, ends| {
            let mut matched = |name: &[u8]| {
                matchers.match_value(MatcherKind::MachoObjcClass, scope, name, hits);
            };
            names.push(part, &mut matched);
            if ends {
                names.finish(&mut matched);
                found.over_budget = found.over_budget.saturating_add(names.overlong());
                *names = Names::new();
            }
        });
    }

    /// Hands a signature to its reader and, once it has gone by, takes in
    /// the Team ID it names and the entitlements it grants.
    fn read_signature(&mut self, fresh: &[u8], fresh_start: u64, last: bool) {
        let (reader, found) = (&mut self.signature, &mut self.found);
        each_part(&mut self.signatures, fresh, fresh_start, last, |part, ends| {
            reader.push(part);
            if !ends {
                return;
            }
            let signature = reader.finish();
            let mut unread = false;
            let mut problem = |error: ReadError| {
                unread = true;
                let count = match error {
                    ReadError::Format(FormatError::Malformed) => &mut found.malformed,
                    ReadError::Format(FormatError::OverBudget(_)) => &mut found.over_budget,
                    ReadError::Unsupported => &mut found.unsupported,
                };
                *count = count.saturating_add(1);
            };
            match signature.team_id {
                Ok(Some(team)) => {
                    found.team_ids.insert(team);
                }
                Ok(None) => {}
                Err(error) => problem(error.into()),
            }
            let granted = match signature.entitlements {
                Ok(granted) => granted.unwrap_or_default(),
                Err(error) => {
                    problem(error);
                    Vec::new()
                }
            };
            found.signatures_unread = found.signatures_unread.saturating_add(u32::from(unread));
            for entitlement in granted {
                if entitlement.key == access::SANDBOX_ENTITLEMENT {
                    found.sandboxed = found.sandboxed.saturating_add(1);
                } else if access::declared(MatcherKind::Entitlement, &entitlement.key).is_some() {
                    let most = found.entitlements.entry(entitlement.key).or_insert(0);
                    *most = entitlement.count.max(*most);
                }
            }
        });
    }

    /// Searches the unmasked bytes of this window.
    fn search_unmasked(&mut self, view: &[u8], view_start: u64, carry: usize, last: bool) {
        if self.tokens.is_empty() {
            return;
        }
        let view_end = view_start.saturating_add(view.len() as u64);
        loop {
            let run = Span {
                start: self.run_start,
                end: self.masks.front().map_or(u64::MAX, |mask| mask.start),
            };
            let window = Window { view, view_start, carry, last };
            if !window.search(self.tokens, run, &mut self.token_hits) {
                // The run goes on in the next window.
                break;
            }
            // A run that ended at no mask ended with the file.
            let Some(mask) = self.masks.pop_front() else { break };
            self.run_start = mask.end;
            if self.run_start >= view_end {
                break;
            }
        }
    }

    /// Searches the script sections of this window.
    fn search_scripts(&mut self, view: &[u8], view_start: u64, carry: usize, last: bool) {
        let view_end = view_start.saturating_add(view.len() as u64);
        while let Some(&section) = self.scripts.front().filter(|section| section.start < view_end) {
            let window = Window { view, view_start, carry, last };
            if !window.search(self.script, section, &mut self.script_hits) {
                break;
            }
            self.scripts.pop_front();
        }
    }

    /// What the pass found, once the last window has gone by.
    pub(super) fn finish(self) -> BinaryFindings {
        let mut found = self.found;
        let problems = self.walker.finish();
        found.malformed = found.malformed.saturating_add(problems.malformed);
        found.over_budget = found.over_budget.saturating_add(problems.over_budget);
        // What the commands name and the file ended before reaching.
        let count = |items: usize| u32::try_from(items).unwrap_or(u32::MAX);
        let unreached = self.name_tables.len() + self.scripts.len() + self.signatures.len();
        found.malformed = found.malformed.saturating_add(count(unreached));
        found.signatures_unread =
            found.signatures_unread.saturating_add(count(self.signatures.len()));

        found.hits = self.table_hits;
        // A file that carries a script is the runtime of that script, and
        // content matchers do not run on runtimes (section 5.2 control 1).
        // That is only known once the load commands have been read, by when
        // some of the file has been searched; so the hits are dropped here.
        if !found.has_script {
            found.hits.merge(&self.token_hits);
        }
        found.hits.merge(&self.script_hits);
        found
    }
}

impl Sink for Binary<'_, '_> {
    fn overlap(&self) -> usize {
        self.tokens.overlap().max(self.script.overlap())
    }

    fn window(&mut self, view: &[u8], carry: usize, last: bool) {
        let fresh = view.get(carry..).unwrap_or_default();
        let fresh_start = self.offset;
        let view_start = fresh_start.saturating_sub(carry as u64);

        // Structure first: it may name ranges that begin in this window.
        self.walker.push(fresh);
        for image in self.walker.take_images() {
            self.admit(image);
        }
        self.read_names(fresh, fresh_start, last);
        self.read_signature(fresh, fresh_start, last);
        self.search_unmasked(view, view_start, carry, last);
        self.search_scripts(view, view_start, carry, last);
        self.offset = fresh_start.saturating_add(fresh.len() as u64);
    }
}

/// The prefixes of an install name that is relative to the bundle.
const BUNDLE_RELATIVE: [&[u8]; 3] = [b"@rpath/", b"@executable_path/", b"@loader_path/"];

/// Matches the install name of a linked library against the `macho_dylib`
/// tokens.
///
/// A token names one path component: the framework folder or the library
/// file, such as `Sentry.framework` in
/// `@rpath/Sentry.framework/Versions/A/Sentry`. Where the library is
/// installed varies from app to app and its name does not.
///
/// An install name that is relative to the bundle is recorded whole as the
/// example. Any other one is a path on some machine, often the one that
/// built the binary, and a record holds no path outside the artifact
/// (evidence format rule 5): of it, only the part from the first component
/// the token matched to the end is recorded, such as `Sentry.framework/Sentry`.
fn match_library(matchers: &Matchers<'_>, scope: Scope, install_name: &[u8], out: &mut HitAcc) {
    let relative = BUNDLE_RELATIVE.iter().any(|prefix| install_name.starts_with(prefix));
    let mut matched = HitAcc::new();
    let mut start = 0;
    for component in install_name.split(|&byte| byte == b'/') {
        let mut here = HitAcc::new();
        matchers.match_value(MatcherKind::MachoDylib, scope, component, &mut here);
        // A token hits a library once, however many components match it.
        for (pattern, _) in here.iter() {
            if matched.count(pattern) == 0 {
                matched.hit(pattern);
                let from = if relative { 0 } else { start };
                out.hit_value(pattern, install_name.get(from..).unwrap_or_default());
            }
        }
        start += component.len() + 1;
    }
}

/// Calls `each` with the part of `fresh` that lies in each range at the
/// front of `ranges`, and with whether the range ends there. A range that
/// has ended is removed. `fresh` starts at file offset `fresh_start`; if it
/// is the last of the file, every range it reaches ends with it.
fn each_part(
    ranges: &mut VecDeque<Span>,
    fresh: &[u8],
    fresh_start: u64,
    last: bool,
    mut each: impl FnMut(&[u8], bool),
) {
    let fresh_end = fresh_start.saturating_add(fresh.len() as u64);
    while let Some(&range) = ranges.front() {
        // A range can only be reached at its start: it is named before the
        // pass gets to it. One the file ends before is left in `ranges`.
        if range.start >= fresh_end {
            break;
        }
        let from = usize::try_from(range.start.saturating_sub(fresh_start)).unwrap_or(usize::MAX);
        let to = usize::try_from(range.end.saturating_sub(fresh_start)).unwrap_or(usize::MAX);
        let part = fresh.get(from.min(fresh.len())..to.min(fresh.len())).unwrap_or_default();
        let ends = last || range.end <= fresh_end;
        each(part, ends);
        if !ends {
            break;
        }
        ranges.pop_front();
    }
}

/// One window of a file, as the reader hands it over.
#[derive(Clone, Copy)]
struct Window<'a> {
    view: &'a [u8],
    /// File offset of the first byte of `view`.
    view_start: u64,
    carry: usize,
    last: bool,
}

impl Window<'_> {
    /// Feeds `engine` the part of this window that lies in `stream`, a range
    /// of the file that is searched as a stream of its own. Returns whether
    /// the stream ends in this window.
    ///
    /// The engine is promised what the reader promises for a whole file. The
    /// part starts with the bytes of the stream that an earlier window
    /// already held, which are the stream's carry; and the part is the
    /// stream's last when the stream, or the file, ends in this window.
    ///
    /// This relies on the stream being known when the pass reaches its
    /// start, which holds for every range a Mach-O image names: then the
    /// bytes an earlier window held were searched as part of the stream.
    fn search(self, engine: &ContentEngine, stream: Span, out: &mut HitAcc) -> bool {
        let view_end = self.view_start.saturating_add(self.view.len() as u64);
        let ends = self.last || stream.end <= view_end;
        let from = stream.start.max(self.view_start);
        let to = stream.end.min(view_end);
        if from >= to {
            return ends;
        }
        let at = |offset: u64| usize::try_from(offset - self.view_start).unwrap_or(usize::MAX);
        let part = self.view.get(at(from)..at(to)).unwrap_or_default();
        let fresh_start = self.view_start.saturating_add(self.carry as u64);
        let carry = usize::try_from(fresh_start.saturating_sub(from)).unwrap_or(usize::MAX);
        engine.scan(part, carry.min(part.len()), ends, out);
        ends
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use proptest::prelude::*;
    use xs_formats::macho_build::{self, Binary as Build, Section, fat};
    use xs_match::PatternId;
    use xs_model::Pack;
    use xs_model::matcher::Boundary;

    use super::*;
    use crate::macos::tests::pack_with;
    use crate::read::{self, HEAD};

    /// Tokens of every kind the pass looks for.
    const TOKENS: [(MatcherKind, &str, Boundary); 7] = [
        (MatcherKind::MachoObjcClass, "MSACAppCenter", Boundary::Exact),
        (MatcherKind::MachoObjcClass, "SentryHub", Boundary::Prefix),
        (MatcherKind::MachoDylib, "Sentry.framework", Boundary::Exact),
        (MatcherKind::MachoToken, "appcenter.ms/logs", Boundary::None),
        (MatcherKind::MachoToken, "in.appcenter.ms", Boundary::Host),
        (MatcherKind::ContentLiteral, "us.i.posthog.com", Boundary::Host),
        (MatcherKind::ContentLiteral, "sentry.javascript.", Boundary::Word),
    ];

    fn pack() -> Pack {
        pack_with(&TOKENS)
    }

    /// Reads `file` through the real reader with `window` fresh bytes per
    /// window.
    fn read(matchers: &Matchers<'_>, scope: Scope, file: &[u8], window: usize) -> BinaryFindings {
        let mut binary = Binary::new(matchers, scope);
        let mut buf = vec![0x55; read::buffer_len_for(binary.overlap(), window)];
        let hashed =
            read::pass(&mut Cursor::new(file), &mut buf, window, &mut binary, |_| true).unwrap();
        assert_eq!(hashed.unwrap().1, file.len() as u64);
        binary.finish()
    }

    /// The count of each of [`TOKENS`], in that order.
    fn counts(matchers: &Matchers<'_>, found: &BinaryFindings) -> Vec<u32> {
        TOKENS
            .iter()
            .map(|&(matcher, literal, _)| {
                let pattern = (0..matchers.pattern_count() as u32)
                    .map(PatternId)
                    .find(|&pattern| {
                        let token = matchers.pattern(pattern).unwrap();
                        token.matcher == matcher && token.token.lit == literal
                    })
                    .unwrap();
                found.hits.count(pattern)
            })
            .collect()
    }

    /// A binary with something for every token, and the same strings where
    /// they must not be found.
    fn app() -> Build {
        Build::new()
            .library("/usr/lib/libSystem.B.dylib")
            .library("@rpath/Sentry.framework/Versions/A/Sentry")
            // Instructions are not searched, whatever bytes they happen to hold.
            .section(Section::code("__TEXT", "__text", b"\x90 in.appcenter.ms \x90"))
            .section(Section::data(
                "__TEXT",
                "__cstring",
                b"https://in.appcenter.ms\0https://api.appcenter.ms/logs?v=1\0us.i.posthog.com\0",
            ))
            .section(Section::data(
                "__TEXT",
                "__objc_classname",
                b"AppDelegate\0MSACAppCenter\0SentryHubInternal\0MSACAppCenterX\0",
            ))
            .section(Section::data("__DATA", "__const", b"MSACAppCenter\0"))
            .signature(&macho_build::signature("com.example.app", Some("ABCDE12345")))
    }

    #[test]
    fn each_part_of_a_binary_is_searched_for_what_belongs_there() {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let found = read(&matchers, Scope::AppCode, &app().build(), 1 << 20);

        // The exact class name once and the prefix once, from the name
        // table alone: not the class name in `__DATA`, and not the longer
        // name. The framework once, from the load commands. Each endpoint
        // once, from `__cstring`: the copy among the instructions is not
        // searched. Script literals are not looked for in a binary's data.
        assert_eq!(counts(&matchers, &found), [1, 1, 1, 1, 1, 0, 0]);
        assert_eq!(found.team_ids, BTreeSet::from(["ABCDE12345".to_string()]));
        assert!(!found.has_script);
        assert_eq!((found.encrypted, found.malformed, found.over_budget), (0, 0, 0));

        // The examples are what a reader can look up with standard tools.
        let example = |index: usize| {
            let (pattern, _) = found.hits.iter().nth(index).unwrap();
            found.hits.example(pattern).map(<[u8]>::to_vec)
        };
        let examples: Vec<Option<Vec<u8>>> = (0..5).map(example).collect();
        assert!(examples.contains(&Some(b"@rpath/Sentry.framework/Versions/A/Sentry".to_vec())));
        assert!(examples.contains(&Some(b"SentryHubInternal".to_vec())));
    }

    /// Design report, M6: the script a runtime carries is searched, and the
    /// runtime around it is not.
    #[test]
    fn an_embedded_script_is_searched_and_the_file_around_it_is_a_runtime() {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let script = b"fetch('https://us.i.posthog.com/e'); sdk='sentry.javascript.'+name; x='in.appcenter.ms'";
        let binary = Build::new()
            .section(Section::data("__TEXT", "__cstring", b"https://in.appcenter.ms\0"))
            .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenter\0"))
            .section(Section::data("__BUN", "__bun", script));
        let found = read(&matchers, Scope::AppCode, &binary.build(), 1 << 20);
        assert!(found.has_script);
        // The class name is a table entry and counts. Both script literals
        // count. The endpoint does not: in `__cstring` it belongs to the
        // runtime, and in the script it is not a script literal.
        assert_eq!(counts(&matchers, &found), [1, 0, 0, 0, 0, 1, 1]);

        // Inside a browser engine nothing free-form is searched, a script
        // section included.
        let found = read(&matchers, Scope::Runtime, &binary.build(), 1 << 20);
        assert!(found.has_script);
        assert_eq!(counts(&matchers, &found), [1, 0, 0, 0, 0, 0, 0]);

        // A section with that name in another segment is not a script.
        let other = Build::new().section(Section::data("__DATA", "__bun", script));
        let found = read(&matchers, Scope::AppCode, &other.build(), 1 << 20);
        assert!(!found.has_script);
        assert_eq!(counts(&matchers, &found), [0, 0, 0, 0, 1, 0, 0]);
    }

    /// Section 5.2 control 1: a file that is a runtime by where it sits is
    /// read for its tables and hashed, and not searched.
    #[test]
    fn a_runtime_file_is_not_searched_but_its_tables_are_read() {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let found = read(&matchers, Scope::Runtime, &app().build(), 1 << 20);
        assert_eq!(counts(&matchers, &found), [1, 1, 1, 0, 0, 0, 0]);
    }

    /// Build plan, task 6: an encrypted binary is recognised. Nothing is
    /// read out of the ciphertext; what is stored in the clear still is.
    #[test]
    fn an_encrypted_binary_is_reported_and_its_ciphertext_left_alone() {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let binary = app().encrypt_from("__TEXT", "__cstring");
        let found = read(&matchers, Scope::AppCode, &binary.build(), 1 << 20);
        assert_eq!(found.encrypted, 1);
        // Only the load commands were read for names.
        assert_eq!(counts(&matchers, &found), [0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(found.team_ids.len(), 1, "the signature is not encrypted");

        // The same file once decrypted gives everything.
        let found = read(&matchers, Scope::AppCode, &binary.crypt_id(0).build(), 1 << 20);
        assert_eq!(found.encrypted, 0);
        assert_eq!(counts(&matchers, &found), [1, 1, 1, 1, 1, 0, 0]);
    }

    #[test]
    fn a_universal_file_counts_each_image() {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let image = app().build();
        let other = app().signature(&macho_build::signature("com.example.app", Some("ZZZZZ99999")));
        let file = fat(&[&image, &other.build()], false);
        let found = read(&matchers, Scope::AppCode, &file, 1 << 20);
        assert_eq!(counts(&matchers, &found), [2, 2, 2, 2, 2, 0, 0]);
        // Images that name different teams are both reported; which one
        // stands for the file is not this pass's decision.
        assert_eq!(found.team_ids.len(), 2);
    }

    #[test]
    fn damage_is_counted_and_what_is_sound_is_still_read() {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();

        // A header and then nothing that could be load commands.
        let mut garbage = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
        garbage.extend_from_slice(b"exposure fixture: not a real program");
        let found = read(&matchers, Scope::AppCode, &garbage, 1 << 20);
        assert_eq!((found.malformed, found.over_budget), (1, 0));
        assert!(found.hits.is_empty());

        // A signature that is not one, and a name no class has.
        let mut table = vec![b'a'; xs_formats::macho::MAX_NAME_BYTES + 1];
        table.extend_from_slice(b"\0MSACAppCenter\0");
        let odd = Build::new()
            .section(Section::data("__TEXT", "__objc_classname", &table))
            .signature(b"not a signature");
        let found = read(&matchers, Scope::AppCode, &odd.build(), 1 << 20);
        assert_eq!((found.malformed, found.over_budget), (1, 1));
        assert_eq!(counts(&matchers, &found), [1, 0, 0, 0, 0, 0, 0]);
        assert!(found.team_ids.is_empty());

        // A file that ends inside its name table: the names before the end
        // are names.
        let whole = app().build();
        let at = whole.windows(13).position(|bytes| bytes == b"MSACAppCenter").unwrap();
        let found = read(&matchers, Scope::AppCode, &whole[..at + 13], 1 << 20);
        assert_eq!(counts(&matchers, &found)[0], 1);
    }

    /// A file without any of the tokens' kinds in the pack is only hashed
    /// and walked: no bytes are repeated between windows.
    #[test]
    fn a_pack_without_literals_asks_for_no_overlap() {
        let pack = pack_with(&[(MatcherKind::MachoObjcClass, "MSACAppCenter", Boundary::Exact)]);
        let matchers = Matchers::build(&pack).unwrap();
        assert_eq!(Binary::new(&matchers, Scope::AppCode).overlap(), 0);
        let found = read(&matchers, Scope::AppCode, &app().build(), HEAD);
        assert_eq!(found.hits.iter().count(), 1);
        assert_eq!(found.team_ids.len(), 1);
    }

    /// Bytes that decide boundaries, plus the tokens themselves, so that
    /// literals and filler collide at the edges of sections and windows.
    fn filler() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(
            prop_oneof![
                prop::sample::select(&TOKENS[..]).prop_map(|(_, lit, _)| lit.as_bytes().to_vec()),
                prop::collection::vec(prop::sample::select(&b"ab.-_ /\0\"x"[..]), 0..6),
            ],
            0..12,
        )
        .prop_map(|pieces| pieces.concat())
    }

    proptest! {
        /// Design report, section 6.4 rule 4: window boundaries cannot
        /// change results. Sections touch each other here, so literals run
        /// up against the edges of masked ranges, name tables and scripts.
        #[test]
        fn findings_do_not_depend_on_the_window(
            parts in prop::collection::vec((0..5u8, filler()), 0..8),
            window in HEAD..200usize,
            universal in any::<bool>(),
            encrypted in any::<bool>(),
            scope in prop::sample::select(&[Scope::AppCode, Scope::Dependency, Scope::Runtime][..]),
        ) {
            let mut binary = Build::new().library("@rpath/Sentry.framework/Sentry");
            for (index, (kind, data)) in parts.iter().enumerate() {
                let name = format!("__part{index}");
                binary = binary.section(match kind {
                    0 => Section::code("__TEXT", &name, data),
                    1 => Section::data("__TEXT", "__objc_classname", data),
                    2 => Section::data("__BUN", "__bun", data),
                    _ => Section::data("__DATA", &name, data),
                });
            }
            if encrypted {
                binary = binary.encrypt_from("__DATA", "__part3");
            }
            binary = binary.signature(&macho_build::signature("id", Some("ABCDE12345")));
            let image = binary.build();
            let file = if universal { fat(&[&image, &image], false) } else { image };

            let pack = pack();
            let matchers = Matchers::build(&pack).unwrap();
            let whole = read(&matchers, scope, &file, file.len() * 2 + HEAD);
            prop_assert_eq!(read(&matchers, scope, &file, window), whole);
        }

        /// The oracle for the unmasked search: each run of unmasked bytes,
        /// cut out of the file and searched whole.
        #[test]
        fn the_unmasked_search_equals_searching_each_run_whole(
            parts in prop::collection::vec((any::<bool>(), filler()), 1..8),
            window in HEAD..120usize,
        ) {
            let mut binary = Build::new();
            for (index, (code, data)) in parts.iter().enumerate() {
                let name = format!("__part{index}");
                binary = binary.section(if *code {
                    Section::code("__TEXT", &name, data)
                } else {
                    Section::data("__DATA", &name, data)
                });
            }
            let file = binary.build();
            let pack = pack();
            let matchers = Matchers::build(&pack).unwrap();

            let mut walker = Walker::new();
            walker.push(&file);
            let image = walker.take_images().pop().unwrap();
            let engine = matchers.content(MatcherKind::MachoToken, Scope::AppCode);
            let mut expected = HitAcc::new();
            let mut start = 0;
            for mask in image.masked.iter().copied().chain([Span { start: u64::MAX, end: u64::MAX }]) {
                let end = (mask.start as usize).min(file.len());
                engine.scan(&file[start..end], 0, true, &mut expected);
                start = (mask.end as usize).min(file.len());
            }

            let found = read(&matchers, Scope::AppCode, &file, window);
            prop_assert_eq!(found.hits, expected);
        }
    }
}
