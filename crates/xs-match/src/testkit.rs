//! Rule packs for tests, built in memory.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use xs_model::Sha256Digest;
use xs_model::matcher::{Boundary, MatcherKind};
use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Pack, Rule, Token};
use xs_model::record::V1;

/// A rule with the given tokens, in the order listed, and no minimums. With
/// no `entity` it is a component.
pub(crate) fn rule(
    id: &str,
    entity: Option<&str>,
    tokens: &[(MatcherKind, &str, Boundary)],
) -> Rule {
    let mut matchers: BTreeMap<MatcherKind, Vec<Token>> = BTreeMap::new();
    for &(kind, lit, at) in tokens {
        matchers.entry(kind).or_default().push(Token { lit: lit.into(), at });
    }
    Rule {
        id: id.into(),
        name: id.into(),
        entity: entity.map(Into::into),
        category: "component".into(),
        sources: vec![],
        notes: vec![],
        matchers,
        min_distinct: BTreeMap::new(),
    }
}

pub(crate) fn entity(id: &str, parent: Option<&str>) -> Entity {
    Entity {
        id: id.into(),
        name: id.into(),
        parent: parent.map(Into::into),
        website: format!("https://{id}.example/"),
        team_ids: Vec::new(),
        app_ids: Vec::new(),
        domains: Vec::new(),
        sources: vec![format!("https://{id}.example/terms")],
    }
}

pub(crate) fn pack_of(entities: Vec<Entity>, rules: Vec<Rule>) -> Pack {
    let layer = Layer {
        format: V1,
        layer: "core".into(),
        version: 1,
        license: "CC-BY-4.0".into(),
        categories: vec![Category {
            id: "component".into(),
            name: "Component".into(),
            headline: false,
        }],
        entities,
        rules,
    };
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }])
        .expect("the test pack is valid")
}

/// A pack of components.
pub(crate) fn pack(rules: Vec<Rule>) -> Pack {
    pack_of(vec![], rules)
}
