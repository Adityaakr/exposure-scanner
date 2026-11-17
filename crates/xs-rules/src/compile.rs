//! The rule-pack source compiler.
//!
//! Rule sources are TOML files a person edits:
//!
//! * `pack.toml` — the layer's name, version and licence, and the fixed list
//!   of categories;
//! * `entities.toml` — the companies rules may name, each with a source;
//! * `sdk/<name>.toml` — one rule per SDK.
//!
//! [`compile`] turns them into one compiled layer: canonical JSON, sorted by
//! id, so the same sources always give the same bytes whatever order the
//! files were listed in. It reads no files itself; the caller passes their
//! content.
//!
//! Compilation is also where the pack's **lints** run. They are policy on
//! top of the structural checks every loader repeats, and they exist because
//! of failures seen on real apps (design report, section 5.2):
//!
//! * A content token (one searched for in free-form bytes) shorter than eight
//!   bytes must use the `exact` boundary. Short literals hit by coincidence.
//! * A content token may not be a bare registrable domain such as
//!   `doubleclick.net`. A browser engine embeds such names, so they tie every
//!   app that embeds one to the company. Name a specific endpoint instead.
//! * Content tokens must state their boundary; there is no default.
//! * No two rules may claim the same token for the same matcher.
//! * Every rule and every entity must cite an `https://` source.
//! * A rule names an entity or declares `component = true`, never neither, so
//!   a forgotten `entity` line cannot silently hide a company.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use xs_model::matcher::{Boundary, MatcherKind};
use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Rule, Token};
use xs_model::record::V1;
use xs_model::{Pack, Sha256Digest, canon, text};

/// A content token shorter than this many bytes needs the `exact` boundary.
pub const MIN_CONTENT_TOKEN_BYTES: usize = 8;

/// One source file: its path inside the layer directory, with `/` separators,
/// and its content.
#[derive(Debug, Clone, Copy)]
pub struct SourceFile<'a> {
    /// Path relative to the layer directory, such as `sdk/sentry.toml`.
    pub path: &'a str,
    /// The file's text.
    pub text: &'a str,
}

/// How strict to be.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Refuse a rule that pins no fixture. Off until the fixture corpus
    /// exists (task 13 of the build plan); the fixture table is parsed and
    /// checked either way.
    pub require_fixtures: bool,
}

/// A compiled layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    /// The layer.
    pub layer: Layer,
    /// Its canonical JSON, the exact bytes that get signed and shipped.
    pub bytes: Vec<u8>,
}

/// Something wrong with the sources.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Problem {
    /// The file the problem is in.
    pub file: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.message)
    }
}

/// Collects problems so that one run reports all of them.
#[derive(Default)]
struct Problems(Vec<Problem>);

impl Problems {
    fn add(&mut self, file: &str, message: impl Into<String>) {
        self.0.push(Problem { file: file.to_string(), message: message.into() });
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSource {
    layer: String,
    version: u32,
    license: String,
    #[serde(default, rename = "category")]
    categories: Vec<Category>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntitiesSource {
    #[serde(default, rename = "entity")]
    entities: Vec<Entity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSource {
    id: String,
    name: String,
    entity: Option<String>,
    #[serde(default)]
    component: bool,
    category: String,
    sources: Vec<String>,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(rename = "match")]
    matchers: toml::Table,
    #[serde(default, rename = "fixture")]
    fixtures: Vec<FixtureSource>,
}

/// A real artifact, pinned by hash, that the rule must match.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureSource {
    sha256: String,
    url: String,
    expect: Vec<String>,
}

/// Compiles the source files of one layer.
///
/// # Errors
///
/// Returns every problem found, sorted, so the same bad sources always give
/// the same report.
pub fn compile(files: &[SourceFile<'_>], options: Options) -> Result<Compiled, Vec<Problem>> {
    let mut problems = Problems::default();
    let mut pack_source: Option<PackSource> = None;
    let mut entities: Vec<Entity> = Vec::new();
    let mut rules: Vec<Rule> = Vec::new();
    let mut seen_paths: Vec<&str> = Vec::new();

    let mut sorted: Vec<&SourceFile<'_>> = files.iter().collect();
    sorted.sort_by_key(|file| file.path);
    for file in sorted {
        if seen_paths.contains(&file.path) {
            problems.add(file.path, "listed more than once");
            continue;
        }
        seen_paths.push(file.path);
        match file.path {
            "pack.toml" => pack_source = parse(file, &mut problems),
            "entities.toml" => {
                if let Some(source) = parse::<EntitiesSource>(file, &mut problems) {
                    entities = source.entities;
                    for entity in &entities {
                        check_https(file.path, "website", &entity.website, &mut problems);
                        check_https(file.path, "source", &entity.source, &mut problems);
                    }
                }
            }
            path => match rule_file_stem(path) {
                Some(stem) => {
                    if let Some(source) = parse::<RuleSource>(file, &mut problems) {
                        rules.extend(lower_rule(path, stem, source, options, &mut problems));
                    }
                }
                None => problems.add(
                    path,
                    "unexpected file; a layer holds pack.toml, entities.toml and sdk/<name>.toml",
                ),
            },
        }
    }

    let Some(pack_source) = pack_source else {
        // Either the file was not given, or it was and its parse error is
        // already in the list.
        if !seen_paths.contains(&"pack.toml") {
            problems.add("pack.toml", "missing");
        }
        return Err(finish(problems));
    };
    check_shared_tokens(&rules, &mut problems);

    let mut layer = Layer {
        format: V1,
        layer: pack_source.layer,
        version: pack_source.version,
        license: pack_source.license,
        categories: pack_source.categories,
        entities,
        rules,
    };
    if layer.version == 0 {
        problems.add("pack.toml", "version must be at least 1");
    }
    // Canonical order: the bytes must not depend on file or table order.
    layer.categories.sort_by(|a, b| a.id.cmp(&b.id));
    layer.entities.sort_by(|a, b| a.id.cmp(&b.id));
    layer.rules.sort_by(|a, b| a.id.cmp(&b.id));

    if !problems.0.is_empty() {
        return Err(finish(problems));
    }
    // The structural checks every loader repeats. Run them here too, so a
    // layer that compiles is a layer that loads.
    let loaded = LoadedLayer { layer: layer.clone(), sha256: Sha256Digest::of(b"") };
    if let Err(error) = Pack::new(vec![loaded]) {
        problems.add("pack.toml", error.to_string());
        return Err(finish(problems));
    }
    match canon::to_vec(&layer) {
        Ok(bytes) => Ok(Compiled { layer, bytes }),
        Err(error) => {
            problems.add("pack.toml", error.to_string());
            Err(finish(problems))
        }
    }
}

fn finish(problems: Problems) -> Vec<Problem> {
    let mut list = problems.0;
    list.sort();
    list.dedup();
    list
}

fn parse<T: for<'de> Deserialize<'de>>(
    file: &SourceFile<'_>,
    problems: &mut Problems,
) -> Option<T> {
    match toml::from_str(file.text) {
        Ok(value) => Some(value),
        Err(error) => {
            problems.add(file.path, error.message());
            None
        }
    }
}

/// `sdk/<stem>.toml` gives `<stem>`; any other path gives `None`.
fn rule_file_stem(path: &str) -> Option<&str> {
    let stem = path.strip_prefix("sdk/")?.strip_suffix(".toml")?;
    (!stem.contains('/')).then_some(stem)
}

fn check_https(file: &str, field: &str, url: &str, problems: &mut Problems) {
    let well_formed = url
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_graphic()));
    if !well_formed {
        problems.add(file, format!("{field} `{url}` must be an https:// URL"));
    }
}

/// Turns one rule file into a [`Rule`], reporting every lint it trips.
fn lower_rule(
    file: &str,
    stem: &str,
    source: RuleSource,
    options: Options,
    problems: &mut Problems,
) -> Option<Rule> {
    let before = problems.0.len();

    if source.id != format!("sdk/{stem}") {
        problems
            .add(file, format!("id `{}` must be `sdk/{stem}` to match the file name", source.id));
    }
    match (&source.entity, source.component) {
        (Some(_), true) => problems.add(file, "a rule has an entity or is a component, not both"),
        (None, false) => problems.add(
            file,
            "name the `entity` that operates this SDK, or set `component = true` for a library with \
             no network side of its own",
        ),
        _ => {}
    }
    if source.sources.is_empty() {
        problems.add(file, "cite at least one source for the tokens");
    }
    for url in &source.sources {
        check_https(file, "source", url, problems);
    }
    for note in &source.notes {
        let well_formed = !note.is_empty()
            && note
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b":_.-".contains(&b));
        if !well_formed {
            problems.add(
                file,
                format!("note `{note}` may only hold lowercase letters, digits and `:_.-`"),
            );
        }
    }

    let (matchers, min_distinct) = lower_match_table(file, &source.matchers, problems);
    check_fixtures(file, &source.fixtures, &matchers, options, problems);

    if problems.0.len() > before {
        return None;
    }
    let mut sources = source.sources;
    sources.sort();
    sources.dedup();
    let mut notes = source.notes;
    notes.sort();
    notes.dedup();
    Some(Rule {
        id: source.id,
        name: source.name,
        entity: source.entity,
        category: source.category,
        sources,
        notes,
        matchers,
        min_distinct,
    })
}

type Matchers = BTreeMap<MatcherKind, Vec<Token>>;
type MinDistinct = BTreeMap<MatcherKind, u32>;

/// Reads the `[match]` table: one array of tokens per matcher kind, plus the
/// optional `min_distinct` table.
fn lower_match_table(
    file: &str,
    table: &toml::Table,
    problems: &mut Problems,
) -> (Matchers, MinDistinct) {
    let mut matchers = Matchers::new();
    let mut min_distinct = MinDistinct::new();
    for (key, value) in table {
        if key == "min_distinct" {
            let Some(entries) = value.as_table() else {
                problems.add(file, "match.min_distinct must be a table of matcher = number");
                continue;
            };
            for (name, minimum) in entries {
                let kind = matcher_kind(name);
                let minimum = minimum.as_integer().and_then(|n| u32::try_from(n).ok());
                match (kind, minimum) {
                    (Some(kind), Some(minimum)) => {
                        min_distinct.insert(kind, minimum);
                    }
                    (None, _) => {
                        problems.add(file, format!("min_distinct names unknown matcher `{name}`"))
                    }
                    (_, None) => {
                        problems.add(file, format!("min_distinct.{name} must be a whole number"))
                    }
                }
            }
            continue;
        }
        let Some(kind) = matcher_kind(key) else {
            problems.add(file, format!("unknown matcher `{key}`"));
            continue;
        };
        let Some(items) = value.as_array() else {
            problems.add(file, format!("{kind} must be an array of tokens"));
            continue;
        };
        let mut tokens: Vec<Token> = Vec::with_capacity(items.len());
        for item in items {
            if let Some(token) = lower_token(file, kind, item, problems) {
                if tokens.iter().any(|earlier| earlier.lit == token.lit) {
                    problems.add(file, format!("{kind} lists token `{}` twice", token.lit));
                } else {
                    tokens.push(token);
                }
            }
        }
        tokens.sort();
        if items.is_empty() {
            problems.add(file, format!("{kind} has no tokens; remove the line"));
        } else if !tokens.is_empty() {
            matchers.insert(kind, tokens);
        }
    }
    (matchers, min_distinct)
}

fn matcher_kind(name: &str) -> Option<MatcherKind> {
    MatcherKind::ALL.into_iter().find(|kind| kind.as_str() == name)
}

fn boundary(name: &str) -> Option<Boundary> {
    [Boundary::None, Boundary::Prefix, Boundary::Exact, Boundary::Word, Boundary::Host]
        .into_iter()
        .find(|boundary| boundary.as_str() == name)
}

/// Reads one token: a bare string, or `{ lit = "…", at = "…" }`.
fn lower_token(
    file: &str,
    kind: MatcherKind,
    item: &toml::Value,
    problems: &mut Problems,
) -> Option<Token> {
    let (lit, at) = match item {
        toml::Value::String(lit) => match kind.default_boundary() {
            Some(at) => (lit.as_str(), at),
            None => {
                problems.add(
                    file,
                    format!(
                        "{kind} token `{lit}` must state its boundary, as {{ lit = \"…\", at = \"…\" }}"
                    ),
                );
                return None;
            }
        },
        toml::Value::Table(table) => {
            let lit = table.get("lit").and_then(toml::Value::as_str);
            let at = table.get("at").and_then(toml::Value::as_str);
            let (Some(lit), Some(at_name), 2) = (lit, at, table.len()) else {
                problems.add(
                    file,
                    format!("a {kind} token table must be exactly {{ lit = \"…\", at = \"…\" }}"),
                );
                return None;
            };
            let Some(at) = boundary(at_name) else {
                problems
                    .add(file, format!("{kind} token `{lit}` has unknown boundary `{at_name}`"));
                return None;
            };
            (lit, at)
        }
        _ => {
            problems.add(file, format!("a {kind} token must be a string or a {{ lit, at }} table"));
            return None;
        }
    };

    let before = problems.0.len();
    if lit.is_empty()
        || lit.len() > text::MAX_TOKEN_BYTES
        || !lit.bytes().all(|b| b.is_ascii_graphic())
    {
        problems.add(
            file,
            format!(
                "{kind} token `{lit}` must be 1 to 255 printable ASCII characters without spaces"
            ),
        );
    }
    if !kind.boundaries().contains(&at) {
        problems.add(file, format!("{kind} token `{lit}` cannot use the `{at}` boundary"));
    }
    if kind.is_content() {
        if lit.len() < MIN_CONTENT_TOKEN_BYTES && at != Boundary::Exact {
            problems.add(
                file,
                format!(
                    "{kind} token `{lit}` is {} bytes; a content token under {MIN_CONTENT_TOKEN_BYTES} \
                     bytes needs the `exact` boundary",
                    lit.len()
                ),
            );
        }
        if is_bare_registrable_domain(lit) {
            problems.add(
                file,
                format!(
                    "{kind} token `{lit}` is a bare registrable domain; name a specific endpoint \
                     instead, because embedded browser engines contain such names"
                ),
            );
        }
    }
    (problems.0.len() == before).then(|| Token { lit: lit.to_string(), at })
}

/// Whether `token` is nothing more than a brand's domain, such as
/// `doubleclick.net`, `.google.com` or `googleapis.com`.
///
/// The Public Suffix List decides. A name directly under a suffix that
/// registries operate (`doubleclick.net`, `example.co.uk`) is bare. So is a
/// suffix that a company operates for its customers or services
/// (`googleapis.com`, `cloudfront.net`), which is that company's whole
/// namespace. A name below either (`api.example.co.uk`,
/// `firebaseinstallations.googleapis.com`) names one endpoint and is fine.
///
/// Only suffixes the list knows count. Without that, any dotted identifier
/// such as `posthog.capture` would look like a domain under an unknown
/// top-level name.
fn is_bare_registrable_domain(token: &str) -> bool {
    let host = token.strip_prefix('.').unwrap_or(token).to_ascii_lowercase();
    let host = host.as_bytes();
    let Some(suffix) = psl::suffix(host).filter(psl::Suffix::is_known) else { return false };
    match suffix.typ() {
        Some(psl::Type::Private) => suffix.as_bytes() == host,
        _ => psl::domain(host).is_some_and(|domain| domain.as_bytes() == host),
    }
}

fn check_fixtures(
    file: &str,
    fixtures: &[FixtureSource],
    matchers: &Matchers,
    options: Options,
    problems: &mut Problems,
) {
    if options.require_fixtures && fixtures.is_empty() {
        problems
            .add(file, "pin at least one fixture: an artifact, by hash, that this rule must match");
    }
    for fixture in fixtures {
        if Sha256Digest::from_hex(&fixture.sha256).is_none() {
            problems.add(
                file,
                format!("fixture sha256 `{}` must be 64 lowercase hex characters", fixture.sha256),
            );
        }
        check_https(file, "fixture url", &fixture.url, problems);
        if fixture.expect.is_empty() {
            problems.add(file, "a fixture must expect at least one matcher to hit");
        }
        for name in &fixture.expect {
            match matcher_kind(name) {
                Some(kind) if matchers.contains_key(&kind) => {}
                Some(kind) => problems
                    .add(file, format!("fixture expects {kind}, which the rule has no tokens for")),
                None => problems.add(file, format!("fixture expects unknown matcher `{name}`")),
            }
        }
    }
}

/// Two rules claiming one token for one matcher would make a single hit
/// accuse two SDKs.
fn check_shared_tokens(rules: &[Rule], problems: &mut Problems) {
    let mut owners: BTreeMap<(MatcherKind, &str), &str> = BTreeMap::new();
    for rule in rules {
        for (&kind, tokens) in &rule.matchers {
            for token in tokens {
                if let Some(owner) = owners.insert((kind, token.lit.as_str()), rule.id.as_str())
                    && owner != rule.id
                {
                    let file = format!("{}.toml", rule.id);
                    problems.add(
                        &file,
                        format!("{kind} token `{}` is already claimed by `{owner}`", token.lit),
                    );
                }
            }
        }
    }
}
