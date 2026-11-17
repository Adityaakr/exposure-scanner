//! Auditing the functions a built binary imports.
//!
//! A program cannot open a socket without importing the function that does
//! it, so the import table is evidence that does not depend on which inputs
//! a test happened to feed the scanner. Of the four no-network checks this is
//! the one that holds on every platform (design report, section 7).

use std::path::Path;

use object::read::{File, NameOrOrdinal, Object as _};

use crate::{Result, read};

/// Socket and name-resolution functions of libc.
const NETWORK_FUNCTIONS: &[&str] = &[
    "accept",
    "accept4",
    "bind",
    "connect",
    "connectx",
    "freeaddrinfo",
    "getaddrinfo",
    "gethostbyaddr",
    "gethostbyname",
    "gethostbyname2",
    "getnameinfo",
    "getpeername",
    "getsockname",
    "getsockopt",
    "listen",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmsg",
    "res_init",
    "res_ninit",
    "res_nquery",
    "res_nsearch",
    "res_query",
    "res_search",
    "send",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setsockopt",
    "shutdown",
    "socket",
    "socketpair",
];

/// Prefixes of networking APIs above libc: Apple's Network and CFNetwork
/// frameworks, libcurl and OpenSSL.
const NETWORK_PREFIXES: &[&str] = &[
    "nw_",
    "CFSocket",
    "CFNetwork",
    "CFStream",
    "CFHost",
    "CFHTTP",
    "curl_",
    "SSL_",
    "BIO_s_connect",
];

/// Fragments of library names that exist to do networking.
const NETWORK_LIBRARIES: &[&str] =
    &["CFNetwork", "Network.framework", "libcurl", "libssl", "libresolv", "libnetwork"];

/// Reduces an import to the plain function name: without the leading
/// underscore Mach-O adds, and without a variant or version suffix such as
/// `$NOCANCEL` or `@GLIBC_2.2.5`.
fn plain_name(symbol: &str) -> &str {
    let symbol = symbol.strip_prefix('_').unwrap_or(symbol);
    symbol.split(['$', '@']).next().unwrap_or(symbol)
}

/// Whether an imported symbol can open, use or resolve for a socket.
pub(crate) fn is_network_symbol(symbol: &str) -> bool {
    let name = plain_name(symbol);
    NETWORK_FUNCTIONS.contains(&name)
        || NETWORK_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || symbol.contains("NSURLSession")
        || symbol.contains("NSURLConnection")
}

/// Whether a library exists to do networking.
pub(crate) fn is_network_library(library: &str) -> bool {
    NETWORK_LIBRARIES.iter().any(|fragment| library.contains(fragment))
}

/// What a binary imports.
pub(crate) struct Audit {
    /// Number of imported symbols seen. Zero would mean the audit saw nothing.
    pub(crate) imports: usize,
    /// Imports that can do networking, sorted.
    pub(crate) network: Vec<String>,
}

/// Lists the networking imports of the binary at `path`.
pub(crate) fn audit(path: &Path) -> Result<Audit> {
    let data = read(path)?;
    let file =
        File::parse(&*data).map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    let imports = file
        .imports()
        .map_err(|error| format!("cannot read imports of {}: {error}", path.display()))?;

    let mut count = 0;
    let mut network = Vec::new();
    for import in imports {
        let import = import
            .map_err(|error| format!("cannot read an import of {}: {error}", path.display()))?;
        count += 1;
        let library = String::from_utf8_lossy(import.library());
        if let NameOrOrdinal::Name(name) = import.name() {
            let name = String::from_utf8_lossy(name);
            if is_network_symbol(&name) {
                network.push(name.into_owned());
            }
        }
        if is_network_library(&library) {
            network.push(format!("library {library}"));
        }
    }
    network.sort();
    network.dedup();
    if count == 0 {
        return Err(format!(
            "{} has no imports at all; the audit cannot see anything",
            path.display()
        ));
    }
    Ok(Audit { imports: count, network })
}

/// `audit-symbols FILE`
pub(crate) fn report(path: &Path) -> Result<()> {
    let audit = audit(path)?;
    if audit.network.is_empty() {
        println!("{}: {} imports, none of them can open a socket", path.display(), audit.imports);
        Ok(())
    } else {
        Err(format!(
            "{} imports networking functions: {}",
            path.display(),
            audit.network.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_functions_are_recognised_in_every_spelling() {
        for symbol in [
            "socket",
            "_socket",
            "_connect",
            "connect@GLIBC_2.2.5",
            "_connect$NOCANCEL",
            "getaddrinfo",
            "_setsockopt",
            "_nw_connection_create",
            "_CFSocketCreate",
            "curl_easy_perform",
            "_OBJC_CLASS_$_NSURLSession",
        ] {
            assert!(is_network_symbol(symbol), "{symbol}");
        }
    }

    #[test]
    fn ordinary_imports_are_not_flagged() {
        for symbol in [
            "_open",
            "_read",
            "_write",
            "_close",
            "_pthread_create",
            "_malloc",
            "_bindtextdomain",
            "_sendfile_is_not_listed",
            "_listener_count",
            "_connection_string",
            "__tlv_bootstrap",
            "_recvx",
        ] {
            assert!(!is_network_symbol(symbol), "{symbol}");
        }
        assert!(is_network_library("/System/Library/Frameworks/CFNetwork.framework/CFNetwork"));
        assert!(!is_network_library("/usr/lib/libSystem.B.dylib"));
    }

    /// The audit is not vacuous: a program that can open a socket is caught.
    /// The test binary is such a program once the control probe is linked
    /// into it, which the reference below ensures.
    #[test]
    fn the_audit_finds_sockets_in_a_program_that_uses_them() {
        let probe: fn() -> std::process::ExitCode = crate::net::probe;
        std::hint::black_box(probe);

        let me = std::env::current_exe().unwrap();
        let audit = audit(&me).unwrap();
        assert!(audit.imports > 0);
        assert!(
            audit.network.iter().any(|name| plain_name(name) == "socket"),
            "{:?}",
            audit.network
        );
    }
}
