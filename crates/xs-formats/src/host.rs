//! Reducing a declared address to its host.
//!
//! A record never holds a URL (design report, C5): a path or a query string
//! can carry a user's token, and only the host says who is on the other end.
//! So the address of an update feed, or a domain listed in a privacy
//! manifest, is cut down to its host here and the rest is dropped.
//!
//! The host comes out in one spelling: ASCII lowercase, no port, no trailing
//! dot. Two apps that name the same host therefore name it identically.
//! Anything that is not plainly a host name is refused rather than guessed
//! at, and the caller reports it as not understood.

/// Longest host name accepted, in bytes: the limit of the DNS.
pub const MAX_HOST_BYTES: usize = 253;

/// Whether `text` is a host name in the form this module produces: labels of
/// lowercase ASCII letters, digits, hyphens and underscores joined by single
/// dots.
fn is_host(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_HOST_BYTES
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
        })
}

/// Normalizes a bare host name such as `Example.COM.`.
///
/// Returns `None` if `text` is not a host name: if it is empty, holds a
/// character a host name cannot, or is not ASCII. An internationalized name
/// must already be in its ASCII form.
#[must_use]
pub fn of_name(text: &str) -> Option<String> {
    let name = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
    is_host(&name).then_some(name)
}

/// The host of an `http` or `https` address, such as
/// `https://example.com/appcast.xml`.
///
/// The scheme may be in any letter case. A user name, password and port are
/// dropped. Returns `None` for any other scheme, an address without a host,
/// and a host that is not a name or an IPv4 address (an IPv6 address in
/// brackets is refused).
#[must_use]
pub fn of_url(text: &str) -> Option<String> {
    let (scheme, rest) = text.trim_matches(|c: char| c.is_ascii_whitespace()).split_once("://")?;
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    // Whatever precedes the last `@` is a user name and password.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host_port)| host_port);
    let host = match host_port.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
        _ => host_port,
    };
    of_name(host)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn an_address_is_cut_down_to_its_host() {
        for (address, host) in [
            ("https://ranchero.com/downloads/netnewswire-release.xml", "ranchero.com"),
            (
                "https://raw.githubusercontent.com/p0deje/Maccy/master/appcast.xml",
                "raw.githubusercontent.com",
            ),
            ("http://example.com", "example.com"),
            ("HTTPS://Updates.Example.COM:8443/feed?channel=beta#top", "updates.example.com"),
            ("https://user:secret@example.com/feed", "example.com"),
            ("https://example.com./feed", "example.com"),
            ("https://example.com?x=https://other.example/", "example.com"),
            ("  https://example.com/feed\n", "example.com"),
            ("http://192.168.1.20:8080/appcast.xml", "192.168.1.20"),
            ("https://xn--bcher-kva.example/feed", "xn--bcher-kva.example"),
        ] {
            assert_eq!(of_url(address).as_deref(), Some(host), "{address}");
        }
    }

    #[test]
    fn what_is_not_plainly_a_host_is_refused() {
        for address in [
            "",
            "example.com/feed",
            "file:///Users/someone/appcast.xml",
            "ftp://example.com/feed",
            "sparkle://example.com/feed",
            "https://",
            "https:///feed",
            "https://[::1]:8080/feed",
            "https://b\u{fc}cher.example/feed",
            "https://exa mple.com/feed",
            "https://example..com/feed",
            "https://example.com:port/feed",
            "https://$(HOST)/feed",
        ] {
            assert_eq!(of_url(address), None, "{address}");
        }
    }

    #[test]
    fn a_bare_name_is_normalized_and_nothing_else_is_a_name() {
        assert_eq!(of_name("Tracker.Example.net").as_deref(), Some("tracker.example.net"));
        assert_eq!(of_name("tracker.example.net.").as_deref(), Some("tracker.example.net"));
        for not in [
            "",
            ".",
            "tracker.example.net/collect",
            "https://tracker.example.net/collect",
            "*.example.net",
            "a b",
        ] {
            assert_eq!(of_name(not), None, "{not}");
        }
    }

    proptest! {
        /// Whatever comes out is a host in the one spelling, and putting it
        /// through again changes nothing.
        #[test]
        fn output_is_a_normalized_host(text in "\\PC{0,60}") {
            for host in [of_url(&text), of_name(&text)].into_iter().flatten() {
                prop_assert!(is_host(&host));
                prop_assert_eq!(of_name(&host), Some(host.clone()));
            }
        }

        #[test]
        fn a_host_survives_the_trip_through_an_address(
            host in "[a-z0-9]{1,8}(\\.[a-z0-9-]{1,8}){0,3}",
            port in prop::option::of(0u16..),
            path in "(/[a-z?#@:]{0,6}){0,3}",
        ) {
            let port = port.map(|port| format!(":{port}")).unwrap_or_default();
            let address = format!("https://{host}{port}{path}");
            prop_assert_eq!(of_url(&address), Some(host));
        }
    }
}
