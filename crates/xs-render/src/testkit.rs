//! Test support: a strict reader of the HTML report, and the check that a
//! report is inert.
//!
//! The reader is written apart from the writer it checks, and it is far
//! stricter than a browser. A browser forgives: it takes a stray `<` for
//! text, an unknown reference for itself, an unquoted attribute for a value.
//! This reader refuses all of that, and reads every `<` as the start of a
//! tag. So whatever a browser would take for an element, this reader takes
//! for one too, and a report it accepts, with only the elements and
//! attributes [`check_inert`] allows, holds nothing a browser would run or
//! load.
//!
//! Only tests enable the `testkit` feature. It is not part of the scanner.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// An element of a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// The tag name.
    pub name: String,
    /// The attributes, in the order written, with references resolved.
    pub attrs: Vec<(String, String)>,
    /// What the element holds.
    pub children: Vec<Node>,
}

/// A child of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// An element.
    Element(Element),
    /// Character data, with references resolved.
    Text(String),
}

impl Element {
    /// The value of the attribute `name`.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(attr, _)| attr == name).map(|(_, value)| value.as_str())
    }

    /// Whether `class` is one of the element's classes.
    #[must_use]
    pub fn has_class(&self, class: &str) -> bool {
        self.attr("class").is_some_and(|classes| classes.split(' ').any(|one| one == class))
    }

    /// All character data inside the element, in document order.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        self.collect_text(&mut out);
        out
    }

    fn collect_text(&self, out: &mut String) {
        for child in &self.children {
            match child {
                Node::Text(text) => out.push_str(text),
                Node::Element(element) => element.collect_text(out),
            }
        }
    }

    /// The element and every element inside it, in document order.
    #[must_use]
    pub fn descendants(&self) -> Vec<&Self> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect<'a>(&'a self, out: &mut Vec<&'a Self>) {
        out.push(self);
        for child in &self.children {
            if let Node::Element(element) = child {
                element.collect(out);
            }
        }
    }

    /// The element whose `id` is `id`.
    #[must_use]
    pub fn by_id(&self, id: &str) -> Option<&Self> {
        self.descendants().into_iter().find(|element| element.attr("id") == Some(id))
    }

    /// Every element named `name`, in document order.
    #[must_use]
    pub fn named(&self, name: &str) -> Vec<&Self> {
        self.descendants().into_iter().filter(|element| element.name == name).collect()
    }
}

/// The one element that has no end tag.
const VOID: &str = "meta";
/// The one element whose content is not markup.
const RAW_TEXT: &str = "style";
/// How a document must start.
const DOCTYPE: &str = "<!doctype html>\n";

/// Reads a report and returns its `html` element.
///
/// # Errors
///
/// Returns what is wrong with the first thing a strict reader does not
/// accept: anything but the doctype, tags with double-quoted attributes,
/// character data, and the five references `&amp;`, `&lt;`, `&gt;`, `&quot;`
/// and `&#39;`.
pub fn parse(document: &str) -> Result<Element, String> {
    let mut rest = document
        .strip_prefix(DOCTYPE)
        .ok_or_else(|| String::from("the document does not start with the doctype"))?;
    // The elements that are open, outermost first. The first is a holder
    // for the root, so every element has a parent to be added to.
    let mut open: Vec<Element> = Vec::from([element("#document")]);

    while !rest.is_empty() {
        let Some(after) = rest.strip_prefix('<') else {
            let end = rest.find('<').unwrap_or(rest.len());
            let (data, tail) = rest.split_at(end);
            if data.contains('>') {
                return Err(format!("a bare `>` in character data: {}", excerpt(data)));
            }
            push(&mut open, Node::Text(resolve(data)?))?;
            rest = tail;
            continue;
        };
        let end = after.find('>').ok_or_else(|| format!("unclosed tag: {}", excerpt(rest)))?;
        let (tag, tail) = after.split_at(end);
        rest = tail.get(1..).unwrap_or("");

        if let Some(name) = tag.strip_prefix('/') {
            let closed = open.pop().ok_or_else(|| format!("`</{name}>` closes nothing"))?;
            if closed.name != name || open.is_empty() {
                return Err(format!("`</{name}>` where `</{}>` was due", closed.name));
            }
            push(&mut open, Node::Element(closed))?;
            continue;
        }
        let mut started = start_tag(tag)?;
        if started.name == VOID {
            push(&mut open, Node::Element(started))?;
        } else if started.name == RAW_TEXT {
            let close = format!("</{RAW_TEXT}>");
            let end = rest.find(&close).ok_or_else(|| format!("`<{RAW_TEXT}>` is not closed"))?;
            let (content, tail) = rest.split_at(end);
            started.children.push(Node::Text(content.to_owned()));
            push(&mut open, Node::Element(started))?;
            rest = tail.get(close.len()..).unwrap_or("");
        } else {
            open.push(started);
        }
    }

    let holder = match (open.pop(), open.is_empty()) {
        (Some(holder), true) => holder,
        (Some(unclosed), false) => return Err(format!("`<{}>` is not closed", unclosed.name)),
        (None, _) => return Err(String::from("the document closes more than it opens")),
    };
    let mut root = None;
    for child in holder.children {
        match child {
            Node::Element(element) if root.is_none() && element.name == "html" => {
                root = Some(element);
            }
            Node::Text(text) if text.chars().all(|c| c == '\n') => {}
            other => return Err(format!("outside the `html` element: {other:?}")),
        }
    }
    root.ok_or_else(|| String::from("the document has no `html` element"))
}

fn element(name: &str) -> Element {
    Element { name: name.to_owned(), attrs: Vec::new(), children: Vec::new() }
}

/// Adds `node` to the innermost open element.
fn push(open: &mut [Element], node: Node) -> Result<(), String> {
    let parent = open.last_mut().ok_or_else(|| String::from("nothing is open"))?;
    parent.children.push(node);
    Ok(())
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Reads what is between `<` and `>` of a start tag: a name, then
/// attributes of the one form ` name="value"`.
fn start_tag(tag: &str) -> Result<Element, String> {
    let bad = || format!("not a start tag: `<{}>`", excerpt(tag));
    let (name, mut rest) = tag.split_at(tag.find(' ').unwrap_or(tag.len()));
    if !is_name(name) {
        return Err(bad());
    }
    let mut started = element(name);
    while !rest.is_empty() {
        let attr = rest.strip_prefix(' ').ok_or_else(bad)?;
        let (attr_name, after) = attr.split_once("=\"").ok_or_else(bad)?;
        let (value, tail) = after.split_once('"').ok_or_else(bad)?;
        if !is_name(attr_name) || value.contains('<') || started.attr(attr_name).is_some() {
            return Err(bad());
        }
        started.attrs.push((attr_name.to_owned(), resolve(value)?));
        rest = tail;
    }
    Ok(started)
}

/// Resolves the five references a report uses. Any other `&` is an error.
fn resolve(data: &str) -> Result<String, String> {
    const REFERENCES: [(&str, char); 5] =
        [("amp;", '&'), ("lt;", '<'), ("gt;", '>'), ("quot;", '"'), ("#39;", '\'')];
    let mut out = String::with_capacity(data.len());
    let mut pieces = data.split('&');
    out.push_str(pieces.next().unwrap_or(""));
    for piece in pieces {
        let (character, tail) = REFERENCES
            .iter()
            .find_map(|&(name, character)| Some((character, piece.strip_prefix(name)?)))
            .ok_or_else(|| format!("a bare `&`: &{}", excerpt(piece)))?;
        out.push(character);
        out.push_str(tail);
    }
    Ok(out)
}

/// The start of `text`, for an error message.
fn excerpt(text: &str) -> String {
    text.chars().take(60).collect()
}

/// The elements a report is made of.
const ELEMENTS: [&str; 33] = [
    "html", "head", "meta", "title", "style", "body", "header", "nav", "main", "section", "div",
    "h1", "h2", "h3", "h4", "h5", "p", "a", "span", "strong", "code", "pre", "ul", "li", "dl",
    "dt", "dd", "table", "thead", "tbody", "tr", "th", "td",
];

/// Checks that a parsed report can run nothing and load nothing.
///
/// * Every element is one of a fixed list that holds no `script`, no frame,
///   no image, no form and no `link`, `base` or `object`.
/// * The only attributes are `class` and `id`, `href` on `a`, `scope` on
///   `th`, `lang` on `html`, and those of `meta`. There is no event handler
///   and no `style` attribute.
/// * Every `href` points into the document itself.
/// * The first elements of the head are the character set and then the
///   content security policy `policy`, ahead of anything that could load.
/// * There is one stylesheet, in the head, and it names no address.
///
/// # Errors
///
/// Returns the first thing that breaks one of these rules.
pub fn check_inert(root: &Element, policy: &str) -> Result<(), String> {
    for element in root.descendants() {
        let name = element.name.as_str();
        if !ELEMENTS.contains(&name) {
            return Err(format!("the element `{name}` is not one a report is made of"));
        }
        for (attr, value) in &element.attrs {
            let allowed = match (name, attr.as_str()) {
                (_, "class" | "id") | ("th", "scope") | ("html", "lang") => true,
                ("a", "href") => value.starts_with('#'),
                ("meta", "charset" | "name" | "content" | "http-equiv") => true,
                _ => false,
            };
            if !allowed {
                return Err(format!("the attribute `{attr}=\"{value}\"` on `{name}`"));
            }
        }
    }

    let head = match root.children.iter().find_map(|child| match child {
        Node::Element(element) => Some(element),
        Node::Text(_) => None,
    }) {
        Some(head) if head.name == "head" => head,
        _ => return Err(String::from("the document does not start with a head")),
    };
    let mut metas = head.children.iter().filter_map(|child| match child {
        Node::Element(element) => Some(element),
        Node::Text(_) => None,
    });
    let charset = metas.next().and_then(|meta| meta.attr("charset"));
    if charset != Some("utf-8") {
        return Err(String::from("the head does not start with the character set"));
    }
    let second = metas.next();
    let is_policy = second.is_some_and(|meta| {
        meta.attr("http-equiv") == Some("Content-Security-Policy")
            && meta.attr("content") == Some(policy)
    });
    if !is_policy {
        return Err(format!("the content security policy is not `{policy}`"));
    }
    // A `meta` can also redirect or set a cookie. Those of a report name
    // the character set, the one policy and three hints to the browser.
    let mut policies = 0;
    for meta in root.named("meta") {
        let is_policy = meta.attr("http-equiv") == Some("Content-Security-Policy");
        policies += usize::from(is_policy);
        let known = is_policy
            || meta.attr("charset").is_some()
            || matches!(meta.attr("name"), Some("referrer" | "viewport" | "color-scheme"));
        if !known || meta.attr("http-equiv").is_some() != is_policy || policies > 1 {
            return Err(format!("an unexpected `meta`: {:?}", meta.attrs));
        }
    }

    let styles = root.named("style");
    let [style] = styles.as_slice() else {
        return Err(format!("{} stylesheets, where one is expected", styles.len()));
    };
    if head.named("style").len() != 1 {
        return Err(String::from("the stylesheet is not in the head"));
    }
    let css = style.text().to_lowercase();
    for loader in ["url(", "@import", "http:", "https:", "//", "expression(", "\\"] {
        if css.contains(loader) {
            return Err(format!("the stylesheet holds `{loader}`"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    const POLICY: &str = "default-src 'none'";

    fn page(body: &str) -> String {
        format!(
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta http-equiv=\"Content-Security-Policy\" content=\"{POLICY}\">\n\
             <title>t</title>\n<style>p > a {{ color: red; }}</style>\n</head>\n\
             <body>{body}</body>\n</html>\n"
        )
    }

    fn inert(body: &str) -> Result<(), String> {
        check_inert(&parse(&page(body))?, POLICY)
    }

    #[test]
    fn reads_elements_attributes_and_references() {
        let root = parse(&page(
            "<p class=\"a b\" id=\"x\">1 &lt; 2 &amp;&amp; <code>&quot;q&quot; &#39;s&#39;</code> &gt;</p>",
        ))
        .unwrap();
        let p = root.by_id("x").unwrap();
        assert_eq!(p.name, "p");
        assert!(p.has_class("a") && p.has_class("b") && !p.has_class("c"));
        assert_eq!(p.text(), "1 < 2 && \"q\" 's' >");
        assert_eq!(root.named("code").len(), 1);
        // The stylesheet is not markup.
        assert_eq!(
            root.named("style")[0].children,
            vec![Node::Text("p > a { color: red; }".into())]
        );
        assert!(root.named("a").is_empty());
    }

    #[test]
    fn refuses_what_a_browser_would_forgive() {
        for (body, expected) in [
            ("a < b", "not a start tag"),
            ("a > b", "bare `>`"),
            ("Q&A", "bare `&`"),
            ("&nbsp;", "bare `&`"),
            ("&#x3c;", "bare `&`"),
            ("<p class=x>", "not a start tag"),
            ("<p class='x'>", "not a start tag"),
            ("<P>", "not a start tag"),
            ("<p  class=\"x\">", "not a start tag"),
            ("<p class=\"x\" class=\"y\">", "not a start tag"),
            ("<br/>", "not a start tag"),
            ("<!-- c -->", "not a start tag"),
            ("<p><b></p></b>", "where `</b>` was due"),
            ("</div>", "where `</body>` was due"),
            ("<p>", "where `</p>` was due"),
        ] {
            let error = parse(&page(body)).unwrap_err();
            assert!(error.contains(expected), "{body}: {error}");
        }
        assert!(parse("<html></html>").unwrap_err().contains("doctype"));
        assert!(parse("<!doctype html>\n<html></html><p></p>").unwrap_err().contains("outside"));
        assert!(parse("<!doctype html>\n<html>").unwrap_err().contains("not closed"));
        assert!(parse("<!doctype html>\n<html><p").unwrap_err().contains("unclosed tag"));
        assert!(parse("<!doctype html>\n</html>").is_err());
    }

    #[test]
    fn an_ordinary_page_is_inert() {
        inert("<h1>Report</h1><p class=\"x\"><a href=\"#records\">records</a></p>").unwrap();
    }

    #[test]
    fn what_could_run_or_load_is_not() {
        for (body, expected) in [
            ("<script>alert(1)</script>", "`script`"),
            ("<img src=\"x\"></img>", "`img`"),
            ("<iframe></iframe>", "`iframe`"),
            ("<form></form>", "`form`"),
            ("<svg></svg>", "`svg`"),
            ("<link rel=\"stylesheet\" href=\"x\"></link>", "`link`"),
            ("<base href=\"x\"></base>", "`base`"),
            ("<p onclick=\"alert(1)\"></p>", "`onclick"),
            ("<p style=\"color:red\"></p>", "`style="),
            ("<a href=\"https://example.com/\">x</a>", "`href="),
            ("<a href=\"javascript:alert(1)\">x</a>", "`href="),
            ("<a href=\"#x\" target=\"_blank\">x</a>", "`target="),
            ("<meta http-equiv=\"refresh\" content=\"0;url=x\">", "unexpected `meta`"),
            ("<style>p{}</style>", "2 stylesheets"),
        ] {
            let error = inert(body).unwrap_err();
            assert!(error.contains(expected), "{body}: {error}");
        }
    }

    #[test]
    fn the_policy_must_come_first_and_be_the_one_expected() {
        let root = parse(&page("")).unwrap();
        assert!(check_inert(&root, "default-src *").unwrap_err().contains("policy"));
        let late = page("").replace("<meta charset=\"utf-8\">\n", "<title>first</title>\n");
        assert!(check_inert(&parse(&late).unwrap(), POLICY).unwrap_err().contains("character set"));
        let loading = page("").replace("color: red", "background: url(x)");
        assert_eq!(
            check_inert(&parse(&loading).unwrap(), POLICY).unwrap_err().to_string(),
            "the stylesheet holds `url(`"
        );
    }
}
