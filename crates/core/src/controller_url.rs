//! The transport rule for a controller's address, which `enrol` and `run` hold it to on a
//! host, and which `landfall host install` holds it to before it connects to one.

use std::net::IpAddr;

use url::Url;

/// Why a `--controller` URL is refused. The URL itself is not repeated: it may
/// hold credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlError {
    /// It does not parse.
    #[error("--controller is not a URL")]
    NotAUrl,
    /// A scheme other than `https` or `http`.
    #[error("--controller must be https://")]
    Scheme,
    /// It is `http://` and the flag was not given.
    #[error(
        "--controller is http://: requests are signed but work contents are visible, so this needs --allow-insecure-controller, and a loopback or tailnet (*.ts.net) name"
    )]
    NeedsFlag,
    /// It is `http://` to a host that is neither loopback nor on a tailnet.
    #[error(
        "--controller is http:// to a host that is not loopback or a tailnet (*.ts.net) name, which --allow-insecure-controller does not cover"
    )]
    NotPrivate,
    /// It carries credentials, a path, a query or a fragment.
    #[error("--controller must be only a scheme, a host and a port")]
    NotABase,
}

/// A controller URL the transport rule allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerUrl(Url);

impl ControllerUrl {
    /// Checks `text` against the transport rule: `https://`, or with
    /// `allow_insecure` also `http://` to a loopback address, `localhost` or a
    /// tailnet name (`*.ts.net`). A tailnet's addresses are not accepted: from
    /// an address alone, `100.64.0.0/10` can't be told from any other carrier's
    /// shared space.
    ///
    /// # Errors
    ///
    /// [`UrlError`] saying which part of the rule it breaks.
    pub fn parse(text: &str, allow_insecure: bool) -> Result<Self, UrlError> {
        let url = Url::parse(text).map_err(|_| UrlError::NotAUrl)?;
        match url.scheme() {
            "https" => {}
            "http" if !allow_insecure => return Err(UrlError::NeedsFlag),
            "http" => {
                if !host_is_private(&url) {
                    return Err(UrlError::NotPrivate);
                }
            }
            _ => return Err(UrlError::Scheme),
        }
        let is_base = url.username().is_empty()
            && url.password().is_none()
            && url.host_str().is_some()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        if !is_base {
            return Err(UrlError::NotABase);
        }
        Ok(Self(url))
    }

    /// The URL as an operator would write it, normalised by the parser and with no
    /// trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str().trim_end_matches('/')
    }

    /// This controller's `path`.
    #[must_use]
    pub fn join(&self, path: &str) -> Url {
        let mut url = self.0.clone();
        url.set_path(path);
        url
    }

    /// Whether it is `https://`.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.0.scheme() == "https"
    }
}

/// The URL's parser has normalised the host: lowercase, an IPv4 address in its
/// dotted form whatever way it was written, an IPv6 address in brackets.
fn host_is_private(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    host == "localhost" || host.ends_with(".ts.net")
}

#[cfg(test)]
mod tests {
    use super::{ControllerUrl, UrlError};

    #[test]
    fn http_controller_needs_the_flag() {
        for (text, flag, want) in [
            ("https://controller.example", false, Ok(())),
            ("https://controller.example", true, Ok(())),
            ("https://controller.example:8443/", false, Ok(())),
            ("http://controller.example", false, Err(UrlError::NeedsFlag)),
            ("http://127.0.0.1:8080", false, Err(UrlError::NeedsFlag)),
            ("http://localhost:8080", false, Err(UrlError::NeedsFlag)),
            (
                "http://controller.tail1234.ts.net",
                false,
                Err(UrlError::NeedsFlag),
            ),
            ("http://127.0.0.1:8080", true, Ok(())),
            ("http://[::1]:8080", true, Ok(())),
            ("http://localhost:8080", true, Ok(())),
            ("http://controller.tail1234.ts.net:8080", true, Ok(())),
            // The flag covers loopback and tailnet names, and nothing else.
            ("http://controller.example", true, Err(UrlError::NotPrivate)),
            ("http://192.0.2.1", true, Err(UrlError::NotPrivate)),
            ("http://100.100.100.100", true, Err(UrlError::NotPrivate)),
            ("http://ts.net", true, Err(UrlError::NotPrivate)),
            ("http://evil-ts.net", true, Err(UrlError::NotPrivate)),
            (
                "http://controller.ts.net.example",
                true,
                Err(UrlError::NotPrivate),
            ),
            ("http://localhost.example", true, Err(UrlError::NotPrivate)),
            ("ftp://controller.example", true, Err(UrlError::Scheme)),
            ("file:///etc/passwd", true, Err(UrlError::Scheme)),
            ("controller.example", true, Err(UrlError::NotAUrl)),
            (
                "https://user:pw@controller.example",
                false,
                Err(UrlError::NotABase),
            ),
            (
                "https://controller.example/prefix",
                false,
                Err(UrlError::NotABase),
            ),
            (
                "https://controller.example/?a=1",
                false,
                Err(UrlError::NotABase),
            ),
            (
                "https://controller.example/#a",
                false,
                Err(UrlError::NotABase),
            ),
        ] {
            assert_eq!(
                ControllerUrl::parse(text, flag).map(|_| ()),
                want,
                "{text} with flag {flag}"
            );
        }
    }

    #[test]
    fn a_refused_url_is_not_repeated() {
        let err = ControllerUrl::parse("http://user:secret@controller.example", false).unwrap_err();
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[test]
    fn it_reads_as_an_operator_would_write_it() {
        for (text, want) in [
            ("https://controller.example", "https://controller.example"),
            ("https://controller.example/", "https://controller.example"),
            (
                "https://CONTROLLER.example:8443",
                "https://controller.example:8443",
            ),
            ("http://[::1]:8080", "http://[::1]:8080"),
        ] {
            assert_eq!(ControllerUrl::parse(text, true).unwrap().as_str(), want);
        }
    }

    #[test]
    fn a_path_is_joined_to_the_base() {
        let url = ControllerUrl::parse("https://controller.example:8443", false).unwrap();
        assert_eq!(
            url.join("/agent/v1/enrol").as_str(),
            "https://controller.example:8443/agent/v1/enrol"
        );
    }

    #[test]
    fn only_https_is_https() {
        assert!(
            ControllerUrl::parse("https://controller.example", false)
                .unwrap()
                .is_https()
        );
        assert!(
            !ControllerUrl::parse("http://localhost", true)
                .unwrap()
                .is_https()
        );
    }
}
