//! The rule-pack source compiler.
//!
//! Rule sources are TOML files a person edits:
//!
//! * `pack.toml` — the layer's name, version and licence, and the fixed list
//!   of categories;
//! * `entities.toml` — the companies rules may name, each with its sources
//!   and the identifiers its own apps and hosts are recognised by;
//! * `sdk/<name>.toml` — one rule per SDK;
//! * `fixes.toml` — optional: what a person can do about a finding, per app
//!   and per SDK ([`xs_model::fix`]).
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
//! * A content token (one searched for in free-form bytes) must be at least
//!   eight bytes, unless its matcher allows the `exact` boundary and the
//!   token uses it. Short literals hit by coincidence.
//! * A content token may not be a bare registrable domain such as
//!   `doubleclick.net`. A browser engine embeds such names, so they tie every
//!   app that embeds one to the company. Name a specific endpoint instead.
//! * Content tokens must state their boundary; there is no default.
//! * No two rules may claim the same token for the same matcher.
//! * Every rule and every entity must cite an `https://` source.
//! * A domain listed for an entity must sit under a public suffix and may
//!   not be one that registries operate, such as `co.uk`: that is nobody's
//!   own domain. A listed app id must read backwards as such a domain, so
//!   that no entry covers the names of a whole registry.
//! * A rule names an entity or declares `component = true`, never neither, so
//!   a forgotten `entity` line cannot silently hide a company.
//! * Every fix cites an `https://` source, and an alternative app names an
//!   `https://` website.
//! * Block lists are conservative (project spec, "Fixes"): a fix may add
//!   hosts only to a rule in a category the headline counts, such as
//!   advertising or analytics, and no host under a domain the pack lists for
//!   another company than the one behind the SDK. Blocking a crash reporter
//!   or another company's servers breaks more than it protects.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use xs_model::fix::{Alternative, AppFix, AppKey, Fixes, NoSetting, SdkFix, Setting};
use xs_model::matcher::{Boundary, MatcherKind};
use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Rule, Token};
use xs_model::record::V1;
use xs_model::{Pack, Sha256Digest, canon, text};

/// A content token shorter than this many bytes is refused unless it uses
/// the `exact` boundary, which only some content matchers allow.
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixesSource {
    #[serde(default, rename = "app")]
    apps: Vec<AppFixSource>,
    #[serde(default, rename = "sdk")]
    sdks: Vec<SdkFix>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppFixSource {
    id: String,
    name: String,
    apps: Vec<AppKey>,
    #[serde(default, rename = "setting")]
    settings: Vec<Setting>,
    #[serde(default)]
    no_setting: Vec<NoSetting>,
    #[serde(default, rename = "alternative")]
    alternatives: Vec<Alternative>,
    sources: Vec<String>,
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
pub fn compile(files: &[SourceFile<'_>]) -> Result<Compiled, Vec<Problem>> {
    let mut problems = Problems::default();
    let mut pack_source: Option<PackSource> = None;
    let mut entities: Vec<Entity> = Vec::new();
    let mut rules: Vec<Rule> = Vec::new();
    let mut fixes = Fixes::default();
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
                    for entity in &mut entities {
                        check_entity(file.path, entity, &mut problems);
                    }
                }
            }
            "fixes.toml" => {
                if let Some(source) = parse::<FixesSource>(file, &mut problems) {
                    fixes = lower_fixes(file.path, source, &mut problems);
                }
            }
            path => match rule_file_stem(path) {
                Some(stem) => {
                    if let Some(source) = parse::<RuleSource>(file, &mut problems) {
                        rules.extend(lower_rule(path, stem, source, &mut problems));
                    }
                }
                None => problems.add(
                    path,
                    "unexpected file; a layer holds pack.toml, entities.toml, fixes.toml and \
                     sdk/<name>.toml",
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
    check_block_lists(&fixes, &pack_source.categories, &entities, &rules, &mut problems);

    let mut layer = Layer {
        format: V1,
        fixes,
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
    layer.fixes.apps.sort_by(|a, b| a.id.cmp(&b.id));
    layer.fixes.sdks.sort_by(|a, b| a.rule.cmp(&b.rule));

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

/// Checks one entity and puts its lists in canonical order.
fn check_entity(file: &str, entity: &mut Entity, problems: &mut Problems) {
    let id = &entity.id;
    check_https(file, "website", &entity.website, problems);
    if entity.sources.is_empty() {
        problems.add(file, format!("entity `{id}` must cite at least one source"));
    }
    for source in &entity.sources {
        check_https(file, "source", source, problems);
    }
    for domain in &entity.domains {
        match public_suffix(domain) {
            None => problems
                .add(file, format!("entity `{id}`: domain `{domain}` is under no public suffix")),
            Some(suffix) if suffix.as_bytes() == domain.as_bytes() && !is_private(&suffix) => {
                problems.add(
                    file,
                    format!(
                        "entity `{id}`: domain `{domain}` is a public suffix; it belongs to a \
                         registry, not to a company"
                    ),
                );
            }
            Some(_) => {}
        }
    }
    for app_id in &entity.app_ids {
        // `com.example.mail` read backwards is `mail.example.com`.
        let mut labels: Vec<&str> = app_id.split('.').collect();
        labels.reverse();
        let host = labels.join(".");
        let registrable = public_suffix(&host).is_some() && psl::domain(host.as_bytes()).is_some();
        if !registrable {
            problems.add(
                file,
                format!(
                    "entity `{id}`: app id `{app_id}` read backwards (`{host}`) is no domain \
                     under a public suffix; an entry must be at least as long as a registrable \
                     domain, such as `com.example`"
                ),
            );
        }
    }
    // Canonical order: the bytes must not depend on the order of a list. A
    // value listed twice is left in for the structural check to name.
    entity.team_ids.sort();
    entity.app_ids.sort();
    entity.domains.sort();
    entity.sources.sort();
    entity.sources.dedup();
}

/// The public suffix `host` ends in, if the Public Suffix List knows one.
fn public_suffix(host: &str) -> Option<psl::Suffix<'_>> {
    psl::suffix(host.as_bytes()).filter(psl::Suffix::is_known)
}

/// Whether a company operates this suffix for its customers or services,
/// such as `githubusercontent.com`, as opposed to a registry.
fn is_private(suffix: &psl::Suffix<'_>) -> bool {
    matches!(suffix.typ(), Some(psl::Type::Private))
}

/// Turns `fixes.toml` into the layer's [`Fixes`], with every list in
/// canonical order, reporting every lint it trips.
fn lower_fixes(file: &str, source: FixesSource, problems: &mut Problems) -> Fixes {
    let mut apps = Vec::with_capacity(source.apps.len());
    for app in source.apps {
        let id = &app.id;
        if app.sources.is_empty() {
            problems.add(file, format!("fix `{id}` must cite at least one source"));
        }
        for url in &app.sources {
            check_https(file, "source", url, problems);
        }
        for alternative in &app.alternatives {
            check_https(file, "website", &alternative.website, problems);
        }
        let mut fix = AppFix {
            id: app.id,
            name: app.name,
            apps: app.apps,
            settings: app.settings,
            no_setting: app.no_setting,
            alternatives: app.alternatives,
            sources: app.sources,
        };
        // The order of steps is the order a reader is told them in, so the
        // settings keep theirs. What they cover is a set.
        fix.apps.sort();
        for setting in &mut fix.settings {
            setting.covers.sort();
        }
        for none in &mut fix.no_setting {
            none.covers.sort();
        }
        fix.sources.sort();
        fix.sources.dedup();
        apps.push(fix);
    }
    let mut sdks = source.sdks;
    for sdk in &mut sdks {
        if sdk.sources.is_empty() {
            problems.add(file, format!("fix for `{}` must cite at least one source", sdk.rule));
        }
        for url in &sdk.sources {
            check_https(file, "source", url, problems);
        }
        sdk.block.sort();
        sdk.sources.sort();
        sdk.sources.dedup();
    }
    Fixes { apps, sdks }
}

/// A block list holds only hosts of advertising, analytics and the like, and
/// no host of another company than the one behind the SDK (project spec,
/// "Fixes").
fn check_block_lists(
    fixes: &Fixes,
    categories: &[Category],
    entities: &[Entity],
    rules: &[Rule],
    problems: &mut Problems,
) {
    for sdk in &fixes.sdks {
        let Some(rule) = rules.iter().find(|rule| rule.id == sdk.rule) else { continue };
        let counted =
            categories.iter().any(|category| category.id == rule.category && category.headline);
        if !counted {
            problems.add(
                "fixes.toml",
                format!(
                    "fix for `{}`: a block list is only for a rule in a category the headline \
                     counts, and `{}` is not one",
                    sdk.rule, rule.category
                ),
            );
        }
        let vendor = rule.entity.as_deref().map(|id| top_company(entities, id));
        for host in &sdk.block {
            let under = |domain: &str| {
                host == domain || host.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
            };
            let other = entities
                .iter()
                .filter(|entity| entity.domains.iter().any(|domain| under(domain)))
                .find(|entity| Some(top_company(entities, &entity.id)) != vendor);
            if let Some(other) = other {
                problems.add(
                    "fixes.toml",
                    format!(
                        "fix for `{}`: host `{host}` is under a domain of `{}`, which is not \
                         the company behind the SDK; blocking it can break that company's apps",
                        sdk.rule, other.id
                    ),
                );
            }
            if public_suffix(host).is_none() {
                problems.add(
                    "fixes.toml",
                    format!("fix for `{}`: host `{host}` is under no public suffix", sdk.rule),
                );
            }
        }
    }
}

/// The id of the company at the top of the ownership chain that starts at
/// `id`. A chain that loops or dangles stops where it does: the structural
/// checks name that problem.
fn top_company<'a>(entities: &'a [Entity], id: &'a str) -> &'a str {
    let mut current = id;
    for _ in 0..entities.len() {
        match entities.iter().find(|entity| entity.id == current).and_then(|e| e.parent.as_deref())
        {
            Some(parent) => current = parent,
            None => break,
        }
    }
    current
}

/// Turns one rule file into a [`Rule`], reporting every lint it trips.
fn lower_rule(file: &str, stem: &str, source: RuleSource, problems: &mut Problems) -> Option<Rule> {
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
    check_fixtures(file, &source.fixtures, &matchers, problems);

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
    MatcherKind::ALL.into_iter().find(|kind| kind.as_str() == name && !kind.boundaries().is_empty())
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
            let remedy = if kind.boundaries().contains(&Boundary::Exact) {
                format!(
                    "a {kind} token under {MIN_CONTENT_TOKEN_BYTES} bytes needs the `exact` boundary"
                )
            } else {
                format!("a {kind} token must be at least {MIN_CONTENT_TOKEN_BYTES} bytes")
            };
            problems.add(file, format!("{kind} token `{lit}` is {} bytes; {remedy}", lit.len()));
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
    let Some(suffix) = public_suffix(&host) else { return false };
    let host = host.as_bytes();
    if is_private(&suffix) {
        suffix.as_bytes() == host
    } else {
        psl::domain(host).is_some_and(|domain| domain.as_bytes() == host)
    }
}

fn check_fixtures(
    file: &str,
    fixtures: &[FixtureSource],
    matchers: &Matchers,
    problems: &mut Problems,
) {
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
