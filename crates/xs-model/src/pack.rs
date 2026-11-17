//! The compiled rule pack.
//!
//! A pack is a collection of **layers**. Each layer is one canonical JSON file
//! with its own licence and its own signature, such as the project's own
//! `core` rules. Layers are only ever combined in memory, never distributed as
//! one merged table, because their licences differ (design report, section 8).
//!
//! A rule is data: lists of literal tokens per matcher kind, tied to one
//! company and one category. There is no regular expression and no script, so
//! a pack cannot run code or stall the scanner.
//!
//! [`Layer`] is the file format. [`Pack`] is what the rest of the scanner
//! uses: layers that passed validation, with lookups by id. A `Pack` cannot be
//! built from data that dangles, so code that holds one may rely on every
//! reference inside it resolving.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::matcher::{Boundary, MatcherKind};
use crate::record::V1;
use crate::text;

/// One independently licensed and signed file of a rule pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    /// Format version of the layer file.
    pub format: V1,
    /// The layer's name, such as `core`.
    pub layer: String,
    /// The layer's version. Together with the hash of the file it tells a
    /// reader exactly which rules produced a report.
    pub version: u32,
    /// SPDX identifier of the licence the layer's data is under.
    pub license: String,
    /// The fixed list of categories rules may use.
    pub categories: Vec<Category>,
    /// The companies rules may name.
    pub entities: Vec<Entity>,
    /// The rules.
    pub rules: Vec<Rule>,
}

/// A kind of service an SDK provides.
///
/// Categories keep update feeds, crash reporting and push services apart from
/// analytics and advertising: hosting is not receiving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    /// The id rules refer to, such as `crash_reporting`.
    pub id: String,
    /// The name shown to a reader.
    pub name: String,
    /// Whether claims in this category count in the report's headline.
    pub headline: bool,
}

/// A company.
///
/// Besides naming the company, an entry says how its own apps and hosts are
/// recognised: by the Apple Team ID in a code signature, by app id, and by
/// domain. Those identifiers are what makes a channel first party, so each
/// belongs to exactly one entity of a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    /// The id rules refer to, such as `google`.
    pub id: String,
    /// The name shown to a reader.
    pub name: String,
    /// The id of the company that owns this one, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The company's own website.
    pub website: String,
    /// The Apple Team IDs the company signs its apps with.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub team_ids: Vec<String>,
    /// App ids of the company's apps, in lowercase. An entry stands for
    /// itself and for every app id below it: `com.example` covers
    /// `com.example.Mail` and not `com.examples`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_ids: Vec<String>,
    /// Domains the company operates. An entry stands for itself and for
    /// every host below it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// Where the facts in this entry come from. Mandatory: an entry without a
    /// source cannot be checked or disputed.
    pub sources: Vec<String>,
}

/// How to recognise one SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The rule's id, which is also the id of the SDK object it produces,
    /// such as `sdk/firebase-crashlytics`.
    pub id: String,
    /// The SDK's name as a reader knows it.
    pub name: String,
    /// The company that operates the SDK's service, or `None` for a component
    /// with no network side of its own.
    pub entity: Option<String>,
    /// The category id.
    pub category: String,
    /// Where each token comes from: vendor documentation or SDK source.
    pub sources: Vec<String>,
    /// Remarks a claim carries along, such as `retired:2025-03-31`.
    pub notes: Vec<String>,
    /// The tokens, per matcher kind.
    #[serde(rename = "match")]
    pub matchers: BTreeMap<MatcherKind, Vec<Token>>,
    /// For a matcher kind listed here, how many different tokens must hit
    /// before the rule fires (design report, section 5.2 control 5).
    pub min_distinct: BTreeMap<MatcherKind, u32>,
}

/// A literal and the boundary it must sit on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    /// The literal.
    pub lit: String,
    /// How it must sit in its surroundings.
    pub at: Boundary,
}

/// A layer together with the hash of the exact bytes it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedLayer {
    /// The parsed layer.
    pub layer: Layer,
    /// SHA-256 of the compiled file.
    pub sha256: Sha256Digest,
}

/// Names the exact rules behind a report: layer, version and file hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRef {
    /// The layer's name.
    pub layer: String,
    /// The layer's version.
    pub version: u32,
    /// SHA-256 of the compiled layer file, in hex.
    pub sha256: String,
}

/// Why a set of layers is not a usable pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    /// A pack needs at least one layer.
    NoLayers,
    /// An id is malformed. Payload: what kind of id, and the id.
    BadId(&'static str, String),
    /// The same id is defined twice. Payload: what kind of id, and the id.
    Duplicate(&'static str, String),
    /// A Team ID, app id or domain listed for an entity is malformed.
    /// Payload: what kind of identifier, and the identifier.
    BadIdentifier(&'static str, String),
    /// A Team ID, app id or domain is listed twice. It names one entity.
    /// Payload: what kind of identifier, and the identifier.
    SharedIdentifier(&'static str, String),
    /// A reference does not resolve. Payload: the referring item, what kind
    /// of thing it refers to, and the missing id.
    Dangling(String, &'static str, String),
    /// An entity is its own ancestor.
    ParentCycle(String),
    /// A text field is empty, too long or holds a control character.
    /// Payload: the item and the field.
    BadText(String, &'static str),
    /// A rule has no tokens at all.
    NoTokens(String),
    /// A token uses a boundary its matcher kind does not allow.
    BadBoundary(String, MatcherKind, Boundary),
    /// A `min_distinct` entry names a matcher the rule does not use, or a
    /// number outside 2 ..= the number of tokens.
    BadMinDistinct(String, MatcherKind),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLayers => f.write_str("a rule pack needs at least one layer"),
            Self::BadId(kind, id) => write!(f, "malformed {kind} id `{id}`"),
            Self::Duplicate(kind, id) => write!(f, "{kind} `{id}` is defined more than once"),
            Self::BadIdentifier(kind, id) => write!(f, "malformed {kind} `{id}`"),
            Self::SharedIdentifier(kind, id) => {
                write!(f, "{kind} `{id}` is listed more than once; it can name only one entity")
            }
            Self::Dangling(from, kind, id) => write!(f, "`{from}` refers to unknown {kind} `{id}`"),
            Self::ParentCycle(id) => write!(f, "entity `{id}` is its own ancestor"),
            Self::BadText(item, field) => {
                write!(f, "`{item}`: {field} is empty, too long or holds a control character")
            }
            Self::NoTokens(rule) => write!(f, "rule `{rule}` has no tokens"),
            Self::BadBoundary(rule, matcher, boundary) => {
                write!(f, "rule `{rule}`: {matcher} tokens cannot use the `{boundary}` boundary")
            }
            Self::BadMinDistinct(rule, matcher) => write!(
                f,
                "rule `{rule}`: min_distinct for {matcher} must be between 2 and the number of \
                 {matcher} tokens"
            ),
        }
    }
}

impl core::error::Error for PackError {}

/// Whether `text` is lowercase words of letters and digits joined by `joiner`.
fn is_slug(text: &str, joiner: char) -> bool {
    !text.is_empty()
        && text.len() <= text::MAX_ID_BYTES
        && text.split(joiner).all(|word| {
            !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// Whether `id` is a well-formed rule id: `sdk/` followed by a hyphenated
/// lowercase name.
#[must_use]
pub fn is_rule_id(id: &str) -> bool {
    id.strip_prefix("sdk/").is_some_and(|name| is_slug(name, '-'))
}

/// Whether `id` is a well-formed entity or layer id: a hyphenated lowercase
/// name.
#[must_use]
pub fn is_entity_id(id: &str) -> bool {
    is_slug(id, '-')
}

/// Whether `id` is a well-formed category id: a lowercase name with
/// underscores.
#[must_use]
pub fn is_category_id(id: &str) -> bool {
    is_slug(id, '_')
}

/// Whether `id` has the shape of an Apple Team ID: ten uppercase letters and
/// digits.
#[must_use]
pub fn is_team_id(id: &str) -> bool {
    id.len() == 10 && id.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// Whether `id` can be listed as an app id of an entity: lowercase labels of
/// letters, digits, hyphens and underscores, joined by single dots. At least
/// two labels, so that no entry can cover a whole top-level name such as
/// `com`.
#[must_use]
pub fn is_app_id_entry(id: &str) -> bool {
    id.len() <= text::MAX_ID_BYTES
        && id.split('.').count() >= 2
        && id.split('.').all(|label| {
            !label.is_empty()
                && label.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
        })
}

/// Whether `domain` can be listed as a domain of an entity: a host name of at
/// least two labels, in the one form records store hosts in.
#[must_use]
pub fn is_domain_entry(domain: &str) -> bool {
    text::is_host(domain) && domain.contains('.')
}

/// Position of an item: which layer, and where in that layer's list.
type Position = (usize, usize);

/// Validated layers with lookups by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pack {
    layers: Vec<LoadedLayer>,
    categories: BTreeMap<String, Position>,
    entities: BTreeMap<String, Position>,
    rules: BTreeMap<String, Position>,
    /// The entity each listed Team ID, app id and domain belongs to.
    team_ids: BTreeMap<String, Position>,
    app_ids: BTreeMap<String, Position>,
    domains: BTreeMap<String, Position>,
}

impl Pack {
    /// Validates `layers` and indexes them.
    ///
    /// Ids must be unique across all layers. How a later layer may override an
    /// earlier one is left for the task that adds a second layer.
    ///
    /// # Errors
    ///
    /// Returns the first problem found, in a fixed order, so the same bad
    /// pack always produces the same message.
    pub fn new(layers: Vec<LoadedLayer>) -> Result<Self, PackError> {
        if layers.is_empty() {
            return Err(PackError::NoLayers);
        }
        let mut pack = Self {
            layers,
            categories: BTreeMap::new(),
            entities: BTreeMap::new(),
            rules: BTreeMap::new(),
            team_ids: BTreeMap::new(),
            app_ids: BTreeMap::new(),
            domains: BTreeMap::new(),
        };
        pack.index()?;
        pack.check_references()?;
        Ok(pack)
    }

    /// Builds the id lookups and checks everything that concerns one item
    /// alone.
    fn index(&mut self) -> Result<(), PackError> {
        let mut layer_names: Vec<&str> = Vec::new();
        for (layer_index, loaded) in self.layers.iter().enumerate() {
            let layer = &loaded.layer;
            if !is_entity_id(&layer.layer) {
                return Err(PackError::BadId("layer", layer.layer.clone()));
            }
            if layer_names.contains(&layer.layer.as_str()) {
                return Err(PackError::Duplicate("layer", layer.layer.clone()));
            }
            layer_names.push(&layer.layer);
            check_text(&layer.layer, "license", &layer.license)?;

            for (index, category) in layer.categories.iter().enumerate() {
                if !is_category_id(&category.id) {
                    return Err(PackError::BadId("category", category.id.clone()));
                }
                check_text(&category.id, "name", &category.name)?;
                insert_unique(
                    &mut self.categories,
                    "category",
                    &category.id,
                    (layer_index, index),
                )?;
            }
            for (index, entity) in layer.entities.iter().enumerate() {
                if !is_entity_id(&entity.id) {
                    return Err(PackError::BadId("entity", entity.id.clone()));
                }
                check_text(&entity.id, "name", &entity.name)?;
                check_text(&entity.id, "website", &entity.website)?;
                if entity.sources.is_empty() {
                    return Err(PackError::BadText(entity.id.clone(), "source"));
                }
                for source in &entity.sources {
                    check_text(&entity.id, "source", source)?;
                }
                let position = (layer_index, index);
                insert_unique(&mut self.entities, "entity", &entity.id, position)?;
                // An identifier names one entity, in whichever layer it is
                // listed. Were two to claim it, who an app belongs to would
                // depend on the order they were read in.
                list_identifiers(
                    &mut self.team_ids,
                    "team id",
                    is_team_id,
                    &entity.team_ids,
                    position,
                )?;
                list_identifiers(
                    &mut self.app_ids,
                    "app id",
                    is_app_id_entry,
                    &entity.app_ids,
                    position,
                )?;
                list_identifiers(
                    &mut self.domains,
                    "domain",
                    is_domain_entry,
                    &entity.domains,
                    position,
                )?;
            }
            for (index, rule) in layer.rules.iter().enumerate() {
                if !is_rule_id(&rule.id) {
                    return Err(PackError::BadId("rule", rule.id.clone()));
                }
                check_rule(rule)?;
                insert_unique(&mut self.rules, "rule", &rule.id, (layer_index, index))?;
            }
        }
        Ok(())
    }

    /// Checks everything that crosses from one item to another.
    fn check_references(&self) -> Result<(), PackError> {
        let entities = || self.layers.iter().flat_map(|loaded| &loaded.layer.entities);
        for entity in entities() {
            if let Some(parent) = &entity.parent
                && self.entity(parent).is_none()
            {
                return Err(PackError::Dangling(entity.id.clone(), "entity", parent.clone()));
            }
        }
        // Every parent now resolves, so a chain can only end at an entity
        // without one. A chain longer than the number of entities must
        // repeat one.
        for entity in entities() {
            let mut current = entity;
            for _ in 0..self.entities.len() {
                match current.parent.as_deref().and_then(|parent| self.entity(parent)) {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
            if current.parent.is_some() {
                // `current` is on the cycle; `entity` may only lead into it.
                // Name the member with the least id, so the same pack gives
                // the same message however many entities it holds.
                let mut least = current;
                let mut member = current;
                while let Some(parent) = member.parent.as_deref().and_then(|id| self.entity(id))
                    && parent.id != current.id
                {
                    member = parent;
                    if member.id < least.id {
                        least = member;
                    }
                }
                return Err(PackError::ParentCycle(least.id.clone()));
            }
        }
        for rule in self.layers.iter().flat_map(|loaded| &loaded.layer.rules) {
            if let Some(entity) = &rule.entity
                && self.entity(entity).is_none()
            {
                return Err(PackError::Dangling(rule.id.clone(), "entity", entity.clone()));
            }
            if self.category(&rule.category).is_none() {
                return Err(PackError::Dangling(
                    rule.id.clone(),
                    "category",
                    rule.category.clone(),
                ));
            }
        }
        Ok(())
    }

    /// The layers, in resolution order.
    #[must_use]
    pub fn layers(&self) -> &[LoadedLayer] {
        &self.layers
    }

    /// Names the exact rules in use, for the report.
    #[must_use]
    pub fn refs(&self) -> Vec<PackRef> {
        self.layers
            .iter()
            .map(|loaded| PackRef {
                layer: loaded.layer.layer.clone(),
                version: loaded.layer.version,
                sha256: loaded.sha256.to_hex(),
            })
            .collect()
    }

    /// The rule with this id.
    #[must_use]
    pub fn rule(&self, id: &str) -> Option<&Rule> {
        let &(layer, index) = self.rules.get(id)?;
        self.layers.get(layer)?.layer.rules.get(index)
    }

    /// The entity with this id.
    #[must_use]
    pub fn entity(&self, id: &str) -> Option<&Entity> {
        let &(layer, index) = self.entities.get(id)?;
        self.layers.get(layer)?.layer.entities.get(index)
    }

    /// The category with this id.
    #[must_use]
    pub fn category(&self, id: &str) -> Option<&Category> {
        let &(layer, index) = self.categories.get(id)?;
        self.layers.get(layer)?.layer.categories.get(index)
    }

    /// The company at the top of the ownership chain that starts at
    /// `entity_id`: the entity itself if it has no parent.
    #[must_use]
    pub fn company_of(&self, entity_id: &str) -> Option<&Entity> {
        let mut current = self.entity(entity_id)?;
        // Validation proved the chain is acyclic; the bound keeps this total
        // without relying on that.
        for _ in 0..self.entities.len() {
            match current.parent.as_deref().and_then(|parent| self.entity(parent)) {
                Some(parent) => current = parent,
                None => break,
            }
        }
        Some(current)
    }

    fn entity_at(&self, &(layer, index): &Position) -> Option<&Entity> {
        self.layers.get(layer)?.layer.entities.get(index)
    }

    /// The entity that lists this Apple Team ID.
    #[must_use]
    pub fn entity_by_team_id(&self, team_id: &str) -> Option<&Entity> {
        self.entity_at(self.team_ids.get(team_id)?)
    }

    /// The entity that lists `app_id` or an app id above it. The longest
    /// listed entry wins, and letter case is ignored: `com.example.mail`
    /// listed by one entity takes `com.example.Mail.Helper` from another
    /// that lists `com.example`.
    #[must_use]
    pub fn entity_by_app_id(&self, app_id: &str) -> Option<&Entity> {
        let app_id = app_id.to_ascii_lowercase();
        let mut candidate = app_id.as_str();
        loop {
            if let Some(position) = self.app_ids.get(candidate) {
                return self.entity_at(position);
            }
            // Drop the last label and try the app id above.
            candidate = candidate.rsplit_once('.')?.0;
        }
    }

    /// The entity that lists `host` or a domain above it. The longest listed
    /// entry wins.
    #[must_use]
    pub fn entity_by_host(&self, host: &str) -> Option<&Entity> {
        let mut candidate = host;
        loop {
            if let Some(position) = self.domains.get(candidate) {
                return self.entity_at(position);
            }
            // Drop the first label and try the domain above.
            candidate = candidate.split_once('.')?.1;
        }
    }

    /// Whether the pack lists a Team ID for the company with this id, under
    /// the company itself or under an entity it owns. Only then does a
    /// signature by a team the pack does not list say that an app is not
    /// that company's.
    #[must_use]
    pub fn lists_team_ids(&self, company_id: &str) -> bool {
        self.team_ids
            .values()
            .filter_map(|position| self.entity_at(position))
            .any(|entity| self.company_of(&entity.id).is_some_and(|top| top.id == company_id))
    }

    /// Every entity, in id order.
    pub fn entities(&self) -> impl Iterator<Item = &Entity> {
        self.entities.values().filter_map(|position| self.entity_at(position))
    }

    /// Every rule, in id order.
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.keys().filter_map(|id| self.rule(id))
    }

    /// Number of rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn insert_unique(
    index: &mut BTreeMap<String, Position>,
    kind: &'static str,
    id: &str,
    position: Position,
) -> Result<(), PackError> {
    if index.insert(id.to_string(), position).is_some() {
        return Err(PackError::Duplicate(kind, id.to_string()));
    }
    Ok(())
}

/// Records that the entity at `position` lists each of `listed`, which are
/// identifiers of one `kind`.
fn list_identifiers(
    index: &mut BTreeMap<String, Position>,
    kind: &'static str,
    well_formed: fn(&str) -> bool,
    listed: &[String],
    position: Position,
) -> Result<(), PackError> {
    for identifier in listed {
        if !well_formed(identifier) {
            return Err(PackError::BadIdentifier(kind, identifier.clone()));
        }
        if index.insert(identifier.clone(), position).is_some() {
            return Err(PackError::SharedIdentifier(kind, identifier.clone()));
        }
    }
    Ok(())
}

fn check_text(item: &str, field: &'static str, value: &str) -> Result<(), PackError> {
    if value.is_empty() || !text::is_clean(value, text::MAX_NAME_BYTES) {
        return Err(PackError::BadText(item.to_string(), field));
    }
    Ok(())
}

fn check_rule(rule: &Rule) -> Result<(), PackError> {
    check_text(&rule.id, "name", &rule.name)?;
    for source in &rule.sources {
        check_text(&rule.id, "source", source)?;
    }
    for note in &rule.notes {
        check_text(&rule.id, "note", note)?;
    }
    if rule.matchers.values().all(Vec::is_empty) {
        return Err(PackError::NoTokens(rule.id.clone()));
    }
    for (&matcher, tokens) in &rule.matchers {
        for (position, token) in tokens.iter().enumerate() {
            if token.lit.is_empty() || !text::is_clean(&token.lit, text::MAX_TOKEN_BYTES) {
                return Err(PackError::BadText(rule.id.clone(), "token"));
            }
            if !matcher.boundaries().contains(&token.at) {
                return Err(PackError::BadBoundary(rule.id.clone(), matcher, token.at));
            }
            if tokens.iter().take(position).any(|earlier| earlier.lit == token.lit) {
                return Err(PackError::Duplicate("token", token.lit.clone()));
            }
        }
    }
    for (&matcher, &minimum) in &rule.min_distinct {
        let available = rule.matchers.get(&matcher).map_or(0, Vec::len);
        if minimum < 2 || usize::try_from(minimum).map_or(true, |minimum| minimum > available) {
            return Err(PackError::BadMinDistinct(rule.id.clone(), matcher));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::vec;

    use super::*;

    pub(crate) fn token(lit: &str, at: Boundary) -> Token {
        Token { lit: lit.into(), at }
    }

    pub(crate) fn layer() -> Layer {
        Layer {
            format: V1,
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![
                Category {
                    id: "crash_reporting".into(),
                    name: "Crash reporting".into(),
                    headline: false,
                },
                Category { id: "component".into(), name: "Component".into(), headline: false },
            ],
            entities: vec![
                Entity {
                    id: "firebase".into(),
                    name: "Firebase".into(),
                    parent: Some("google".into()),
                    website: "https://firebase.google.com/".into(),
                    team_ids: vec![],
                    app_ids: vec!["com.google.firebase".into()],
                    domains: vec!["firebase.google.com".into(), "firebaseio.com".into()],
                    sources: vec!["https://firebase.google.com/terms".into()],
                },
                Entity {
                    id: "google".into(),
                    name: "Google LLC".into(),
                    parent: None,
                    website: "https://about.google/".into(),
                    team_ids: vec!["EQHXZ8M8AV".into()],
                    app_ids: vec!["com.google".into()],
                    domains: vec!["google.com".into()],
                    sources: vec!["https://about.google/".into()],
                },
            ],
            rules: vec![
                Rule {
                    id: "sdk/firebase-crashlytics".into(),
                    name: "Firebase Crashlytics".into(),
                    entity: Some("firebase".into()),
                    category: "crash_reporting".into(),
                    sources: vec!["https://example.com/source".into()],
                    notes: vec![],
                    matchers: BTreeMap::from([
                        (
                            MatcherKind::AndroidClassPrefix,
                            vec![token("com.google.firebase.crashlytics.", Boundary::Prefix)],
                        ),
                        (
                            MatcherKind::MachoToken,
                            vec![
                                token("FIRCLSReportManager", Boundary::Word),
                                token("FIRCLSSettings", Boundary::Word),
                            ],
                        ),
                    ]),
                    min_distinct: BTreeMap::from([(MatcherKind::MachoToken, 2)]),
                },
                Rule {
                    id: "sdk/sparkle".into(),
                    name: "Sparkle".into(),
                    entity: None,
                    category: "component".into(),
                    sources: vec!["https://example.com/source".into()],
                    notes: vec![],
                    matchers: BTreeMap::from([(
                        MatcherKind::AppleFramework,
                        vec![token("Sparkle.framework", Boundary::Exact)],
                    )]),
                    min_distinct: BTreeMap::new(),
                },
            ],
        }
    }

    pub(crate) fn pack_of(layer: Layer) -> Result<Pack, PackError> {
        Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"test") }])
    }

    #[test]
    fn a_valid_layer_indexes() {
        let pack = pack_of(layer()).unwrap();
        assert_eq!(pack.rule_count(), 2);
        assert_eq!(pack.rule("sdk/sparkle").unwrap().name, "Sparkle");
        assert!(pack.rule("sdk/missing").is_none());
        assert_eq!(pack.category("component").unwrap().name, "Component");
        let ids: Vec<&str> = pack.rules().map(|rule| rule.id.as_str()).collect();
        assert_eq!(ids, ["sdk/firebase-crashlytics", "sdk/sparkle"]);
        assert_eq!(pack.refs()[0].layer, "core");
        assert_eq!(pack.refs()[0].sha256, Sha256Digest::of(b"test").to_hex());
    }

    #[test]
    fn company_is_the_top_of_the_ownership_chain() {
        let pack = pack_of(layer()).unwrap();
        assert_eq!(pack.company_of("firebase").unwrap().id, "google");
        assert_eq!(pack.company_of("google").unwrap().id, "google");
        assert!(pack.company_of("nobody").is_none());
    }

    #[test]
    fn a_team_id_names_the_entity_that_lists_it() {
        let pack = pack_of(layer()).unwrap();
        assert_eq!(pack.entity_by_team_id("EQHXZ8M8AV").unwrap().id, "google");
        assert!(pack.entity_by_team_id("ABCDE12345").is_none());
        // A Team ID is an exact value: no other spelling of it is one.
        assert!(pack.entity_by_team_id("eqhxz8m8av").is_none());
        assert!(pack.entity_by_team_id("EQHXZ8M8A").is_none());
    }

    #[test]
    fn an_app_id_belongs_to_the_longest_entry_at_or_above_it() {
        let pack = pack_of(layer()).unwrap();
        let owner = |app_id| pack.entity_by_app_id(app_id).map(|entity| entity.id.as_str());
        assert_eq!(owner("com.google"), Some("google"));
        assert_eq!(owner("com.google.Chrome"), Some("google"));
        assert_eq!(owner("COM.Google.Chrome.helper"), Some("google"), "case is ignored");
        assert_eq!(owner("com.google.firebase.quickstart"), Some("firebase"), "longest wins");
        // An entry covers what is below it on a label boundary, nothing else.
        assert_eq!(owner("com.googleplex.app"), None);
        assert_eq!(owner("com.google-fan.app"), None);
        assert_eq!(owner("com"), None);
        assert_eq!(owner("org.google.Chrome"), None);
        assert_eq!(owner(""), None);
    }

    #[test]
    fn a_host_belongs_to_the_longest_domain_at_or_above_it() {
        let pack = pack_of(layer()).unwrap();
        let owner = |host| pack.entity_by_host(host).map(|entity| entity.id.as_str());
        assert_eq!(owner("google.com"), Some("google"));
        assert_eq!(owner("dl.google.com"), Some("google"));
        assert_eq!(owner("firebase.google.com"), Some("firebase"), "longest wins");
        assert_eq!(owner("console.firebase.google.com"), Some("firebase"));
        assert_eq!(owner("app.firebaseio.com"), Some("firebase"));
        assert_eq!(owner("notgoogle.com"), None);
        assert_eq!(owner("google.com.evil.example"), None);
        assert_eq!(owner("com"), None);
        assert_eq!(owner(""), None);
    }

    #[test]
    fn a_company_lists_team_ids_through_the_entities_it_owns() {
        let mut layer = layer();
        assert!(pack_of(layer.clone()).unwrap().lists_team_ids("google"));
        assert!(!pack_of(layer.clone()).unwrap().lists_team_ids("firebase"), "not a company");
        assert!(!pack_of(layer.clone()).unwrap().lists_team_ids("nobody"));

        // Only the subsidiary lists one: it still counts for the company.
        layer.entities[0].team_ids = layer.entities[1].team_ids.split_off(0);
        assert!(pack_of(layer.clone()).unwrap().lists_team_ids("google"));
        layer.entities[0].team_ids.clear();
        assert!(!pack_of(layer).unwrap().lists_team_ids("google"));
    }

    #[test]
    fn entities_are_listed_in_id_order() {
        let pack = pack_of(layer()).unwrap();
        let ids: Vec<&str> = pack.entities().map(|entity| entity.id.as_str()).collect();
        assert_eq!(ids, ["firebase", "google"]);
    }

    #[test]
    fn rejects_malformed_and_shared_identifiers() {
        for bad in ["eqhxz8m8av", "EQHXZ8M8A", "EQHXZ8M8AVX", "EQHXZ8M8A-", ""] {
            assert_eq!(
                broken(|l| l.entities[1].team_ids = vec![bad.into()]),
                PackError::BadIdentifier("team id", bad.into())
            );
        }
        for bad in ["com", "com.Google", "com..google", "com.google.", ".com.google", "com google"]
        {
            assert_eq!(
                broken(|l| l.entities[1].app_ids = vec![bad.into()]),
                PackError::BadIdentifier("app id", bad.into())
            );
        }
        for bad in ["com", "Google.com", "google.com.", "https://google.com", "google.com/x"] {
            assert_eq!(
                broken(|l| l.entities[1].domains = vec![bad.into()]),
                PackError::BadIdentifier("domain", bad.into())
            );
        }
        // One identifier, one entity.
        assert_eq!(
            broken(|l| l.entities[0].team_ids = vec!["EQHXZ8M8AV".into()]),
            PackError::SharedIdentifier("team id", "EQHXZ8M8AV".into())
        );
        assert_eq!(
            broken(|l| l.entities[0].app_ids.push("com.google".into())),
            PackError::SharedIdentifier("app id", "com.google".into())
        );
        assert_eq!(
            broken(|l| l.entities[1].domains.push("firebaseio.com".into())),
            PackError::SharedIdentifier("domain", "firebaseio.com".into())
        );
        assert_eq!(
            broken(|l| l.entities[1].domains.push("google.com".into())),
            PackError::SharedIdentifier("domain", "google.com".into())
        );
    }

    #[test]
    fn an_entity_needs_a_source() {
        assert_eq!(
            broken(|l| l.entities[0].sources.clear()),
            PackError::BadText("firebase".into(), "source")
        );
        assert_eq!(
            broken(|l| l.entities[0].sources.push(String::new())),
            PackError::BadText("firebase".into(), "source")
        );
    }

    #[test]
    fn an_entity_without_identifiers_reads_and_writes_as_before() {
        let mut layer = layer();
        for entity in &mut layer.entities {
            entity.team_ids.clear();
            entity.app_ids.clear();
            entity.domains.clear();
        }
        let json = crate::canon::to_string(&layer).unwrap();
        assert!(
            !json.contains("team_ids") && !json.contains("app_ids") && !json.contains("domains")
        );
        assert_eq!(serde_json::from_str::<Layer>(&json).unwrap(), layer);
    }

    #[test]
    fn the_layer_round_trips_through_json() {
        let original = layer();
        let json = crate::canon::to_string(&original).unwrap();
        assert_eq!(serde_json::from_str::<Layer>(&json).unwrap(), original);
    }

    fn broken(change: impl FnOnce(&mut Layer)) -> PackError {
        let mut layer = layer();
        change(&mut layer);
        pack_of(layer).unwrap_err()
    }

    #[test]
    fn rejects_malformed_and_duplicate_ids() {
        assert_eq!(Pack::new(vec![]), Err(PackError::NoLayers));
        assert_eq!(
            broken(|l| l.rules[0].id = "Firebase".into()),
            PackError::BadId("rule", "Firebase".into())
        );
        assert_eq!(
            broken(|l| l.rules[1].id = "sdk/Sparkle".into()),
            PackError::BadId("rule", "sdk/Sparkle".into())
        );
        assert_eq!(
            broken(|l| l.entities[0].id = "fire base".into()),
            PackError::BadId("entity", "fire base".into())
        );
        assert_eq!(
            broken(|l| l.rules[1].id = "sdk/firebase-crashlytics".into()),
            PackError::Duplicate("rule", "sdk/firebase-crashlytics".into())
        );
        assert_eq!(
            broken(|l| l.categories[1].id = "crash_reporting".into()),
            PackError::Duplicate("category", "crash_reporting".into())
        );
    }

    #[test]
    fn rejects_dangling_references_and_cycles() {
        assert_eq!(
            broken(|l| l.rules[0].entity = Some("nobody".into())),
            PackError::Dangling("sdk/firebase-crashlytics".into(), "entity", "nobody".into())
        );
        assert_eq!(
            broken(|l| l.rules[0].category = "astrology".into()),
            PackError::Dangling("sdk/firebase-crashlytics".into(), "category", "astrology".into())
        );
        assert_eq!(
            broken(|l| l.entities[0].parent = Some("nobody".into())),
            PackError::Dangling("firebase".into(), "entity", "nobody".into())
        );
        // A dangling parent further up the chain names the entity that has
        // it, not the first entity whose chain passes through it.
        assert_eq!(
            broken(|l| l.entities[1].parent = Some("nobody".into())),
            PackError::Dangling("google".into(), "entity", "nobody".into())
        );
        assert_eq!(
            broken(|l| l.entities[1].parent = Some("firebase".into())),
            PackError::ParentCycle("firebase".into())
        );
        // firebase's parent is google, which here is its own parent. Only
        // google is its own ancestor; firebase merely leads to it.
        assert_eq!(
            broken(|l| l.entities[1].parent = Some("google".into())),
            PackError::ParentCycle("google".into())
        );
    }

    #[test]
    fn rejects_bad_tokens() {
        assert_eq!(
            broken(|l| l.rules[1].matchers.clear()),
            PackError::NoTokens("sdk/sparkle".into())
        );
        assert_eq!(
            broken(|l| {
                l.rules[1]
                    .matchers
                    .insert(MatcherKind::AppleFramework, vec![token("Sparkle", Boundary::None)]);
            }),
            PackError::BadBoundary(
                "sdk/sparkle".into(),
                MatcherKind::AppleFramework,
                Boundary::None
            )
        );
        assert_eq!(
            broken(|l| {
                l.rules[1]
                    .matchers
                    .insert(MatcherKind::AppleFramework, vec![token("", Boundary::Exact)]);
            }),
            PackError::BadText("sdk/sparkle".into(), "token")
        );
        for at in [Boundary::Exact, Boundary::Host] {
            assert_eq!(
                broken(|l| {
                    l.rules[1]
                        .matchers
                        .insert(MatcherKind::UpdateFeed, vec![token("updates.example.com", at)]);
                }),
                PackError::BadBoundary("sdk/sparkle".into(), MatcherKind::UpdateFeed, at)
            );
        }
        assert_eq!(
            broken(|l| {
                let tokens = l.rules[1].matchers.get_mut(&MatcherKind::AppleFramework).unwrap();
                tokens.push(token("Sparkle.framework", Boundary::Exact));
            }),
            PackError::Duplicate("token", "Sparkle.framework".into())
        );
    }

    #[test]
    fn rejects_impossible_minimums() {
        for minimum in [0, 1, 3] {
            assert_eq!(
                broken(|l| {
                    l.rules[0].min_distinct.insert(MatcherKind::MachoToken, minimum);
                }),
                PackError::BadMinDistinct(
                    "sdk/firebase-crashlytics".into(),
                    MatcherKind::MachoToken
                )
            );
        }
        assert_eq!(
            broken(|l| {
                l.rules[0].min_distinct.insert(MatcherKind::DexString, 2);
            }),
            PackError::BadMinDistinct("sdk/firebase-crashlytics".into(), MatcherKind::DexString)
        );
    }

    #[test]
    fn id_syntax() {
        assert!(is_rule_id("sdk/firebase-crashlytics"));
        assert!(is_rule_id("sdk/a1"));
        for bad in
            ["sdk/", "firebase", "sdk/-a", "sdk/a-", "sdk/a--b", "sdk/A", "sdk/a_b", "sdk/a/b"]
        {
            assert!(!is_rule_id(bad), "{bad}");
        }
        assert!(is_category_id("crash_reporting"));
        assert!(!is_category_id("crash-reporting"));
        assert!(is_entity_id("functional-software"));
        assert!(!is_entity_id("functional_software"));
    }
}
