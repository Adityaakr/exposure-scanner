//! The one way text reaches an HTML document.
//!
//! App names, versions, class names and paths are chosen by whoever built
//! the app that was scanned, so the report treats every one of them as
//! hostile (design report, section 3, M3). Rather than remember to escape at
//! each place a value is written, the writer makes forgetting impossible:
//!
//! * Markup is `&'static str`. Only text that is part of this program can be
//!   written as it is.
//! * Any other string goes through [`Markup::text`], which escapes it.
//! * An attribute value is one of the three shapes of [`Value`]: a fixed
//!   string, or an anchor or link built from a fixed prefix and the hex of a
//!   digest. No string read from a file can be an attribute value at all.
//!
//! So a value from a scanned app can only ever be character data between
//! tags, with the five characters that could end it replaced.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use xs_model::{Sha256Digest, text};

/// The value of an attribute.
#[derive(Clone, Copy)]
pub(crate) enum Value<'a> {
    /// A string that is part of this program.
    Fixed(&'static str),
    /// The name of an anchor: a fixed prefix and the hex of a digest, such
    /// as `r-8aa0…`.
    Anchor(&'static str, &'a Sha256Digest),
    /// A link to such an anchor in the same document: `#r-8aa0…`. The report
    /// links nowhere else.
    Link(&'static str, &'a Sha256Digest),
}

/// An attribute: a fixed name and its value.
pub(crate) type Attr<'a> = (&'static str, Value<'a>);

/// An HTML document under construction.
pub(crate) struct Markup {
    out: String,
    /// The elements that are open, innermost last.
    open: Vec<&'static str>,
}

impl Markup {
    pub(crate) const fn new() -> Self {
        Self { out: String::new(), open: Vec::new() }
    }

    /// Writes markup that is part of this program, as it is.
    pub(crate) fn raw(&mut self, markup: &'static str) {
        self.out.push_str(markup);
    }

    /// Writes a value as character data.
    pub(crate) fn text(&mut self, value: &str) {
        escape_into(&mut self.out, value);
    }

    /// Writes a number.
    pub(crate) fn number(&mut self, value: u64) {
        // Writing to a string cannot fail.
        let _ = write!(self.out, "{value}");
    }

    /// Opens an element. [`close`](Self::close) ends it.
    pub(crate) fn open(&mut self, tag: &'static str, attrs: &[Attr<'_>]) {
        self.out.push('<');
        self.out.push_str(tag);
        for &(name, value) in attrs {
            self.out.push(' ');
            self.out.push_str(name);
            self.out.push_str("=\"");
            match value {
                Value::Fixed(fixed) => self.out.push_str(fixed),
                Value::Anchor(prefix, digest) => {
                    let _ = write!(self.out, "{prefix}{digest}");
                }
                Value::Link(prefix, digest) => {
                    let _ = write!(self.out, "#{prefix}{digest}");
                }
            }
            self.out.push('"');
        }
        self.out.push('>');
        self.open.push(tag);
    }

    /// Opens an element that has a class and no other attribute.
    pub(crate) fn open_class(&mut self, tag: &'static str, class: &'static str) {
        self.open(tag, &[("class", Value::Fixed(class))]);
    }

    /// Ends the innermost open element.
    pub(crate) fn close(&mut self) {
        if let Some(tag) = self.open.pop() {
            self.out.push_str("</");
            self.out.push_str(tag);
            self.out.push('>');
        }
    }

    /// Writes an element that holds one value as character data.
    pub(crate) fn element(&mut self, tag: &'static str, attrs: &[Attr<'_>], value: &str) {
        self.open(tag, attrs);
        self.text(value);
        self.close();
    }

    /// Writes an element with a class that holds one value.
    pub(crate) fn classed(&mut self, tag: &'static str, class: &'static str, value: &str) {
        self.element(tag, &[("class", Value::Fixed(class))], value);
    }

    /// Whether nothing has been written.
    pub(crate) fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Writes a piece that this writer built, as it is. Elements the piece
    /// left open are ended first.
    pub(crate) fn append(&mut self, piece: Self) {
        self.out.push_str(&piece.finish());
    }

    /// The document. Elements still open are ended first, so what comes out
    /// is well nested whatever the caller did.
    pub(crate) fn finish(mut self) -> String {
        while !self.open.is_empty() {
            self.close();
        }
        self.out
    }
}

/// Appends `value` to `out` as HTML character data.
///
/// The five characters that could end character data or an attribute value
/// are replaced by references. A character a record may not store (a control
/// character, or one that reorders text on screen) becomes U+FFFD: records
/// hold none, and a value from anywhere else gets the same treatment here.
fn escape_into(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other if text::is_storable(other) => out.push(other),
            _ => out.push('\u{fffd}'),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use proptest::prelude::*;

    use super::*;

    fn escaped(value: &str) -> String {
        let mut markup = Markup::new();
        markup.text(value);
        markup.finish()
    }

    #[test]
    fn the_five_characters_become_references() {
        assert_eq!(
            escaped(r#"<script>alert("x & y")</script> 'z'"#),
            "&lt;script&gt;alert(&quot;x &amp; y&quot;)&lt;/script&gt; &#39;z&#39;"
        );
        // An escaped value is escaped again: nothing is ever taken for markup.
        assert_eq!(escaped("&lt;b&gt;"), "&amp;lt;b&amp;gt;");
    }

    #[test]
    fn ordinary_text_is_left_alone() {
        assert_eq!(escaped("Bitwarden 2026.9.1 – “日本語”"), "Bitwarden 2026.9.1 – “日本語”");
    }

    #[test]
    fn control_and_reordering_characters_are_replaced() {
        assert_eq!(
            escaped("a\u{0}b\u{1b}[31m\u{202e}c\n"),
            "a\u{fffd}b\u{fffd}[31m\u{fffd}c\u{fffd}"
        );
    }

    #[test]
    fn elements_nest_and_attributes_take_only_fixed_text_or_a_digest() {
        let digest = Sha256Digest::of(b"record");
        let mut markup = Markup::new();
        markup.open("p", &[("class", Value::Fixed("note")), ("id", Value::Anchor("r-", &digest))]);
        markup.element("a", &[("href", Value::Link("r-", &digest))], "a <b> c");
        markup.number(42);
        markup.raw("<br>");
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(
            markup.finish(),
            alloc::format!(
                "<p class=\"note\" id=\"r-{hex}\"><a href=\"#r-{hex}\">a &lt;b&gt; c</a>42<br></p>"
            )
        );
    }

    #[test]
    fn a_piece_is_appended_as_it_was_written_and_closed() {
        let mut piece = Markup::new();
        assert!(piece.is_empty());
        piece.open("li", &[]);
        piece.text("a <b>");
        assert!(!piece.is_empty());
        let mut markup = Markup::new();
        markup.open("ul", &[]);
        markup.append(piece);
        assert_eq!(markup.finish(), "<ul><li>a &lt;b&gt;</li></ul>");
    }

    #[test]
    fn closing_more_than_was_opened_writes_nothing() {
        let mut markup = Markup::new();
        markup.classed("em", "x", "y");
        markup.close();
        assert_eq!(markup.finish(), "<em class=\"x\">y</em>");
    }

    proptest! {
        /// Whatever the value, what is written holds none of the characters
        /// that could end character data or an attribute value, and every
        /// ampersand in it starts one of the five references.
        #[test]
        fn no_value_can_leave_character_data(value in any::<String>()) {
            let out = escaped(&value);
            prop_assert!(!out.contains(['<', '>', '"', '\'']));
            for (at, _) in out.match_indices('&') {
                let rest = &out[at..];
                prop_assert!(
                    ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"]
                        .iter()
                        .any(|reference| rest.starts_with(reference)),
                    "{rest}"
                );
            }
            prop_assert!(out.chars().all(text::is_storable));
        }
    }
}
