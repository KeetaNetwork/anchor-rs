//! Operation endpoint templates and `{param}` substitution.

use alloc::string::{String, ToString};

use keetanetwork_anchor::signing::Url;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::error::AnchorClientError;

/// The characters JavaScript's `encodeURIComponent` leaves unescaped:
/// alphanumerics plus `- _ . ! ~ * ' ( )`. Substituted values are encoded
/// against this set so a filled template matches the URL a JavaScript client
/// would build for the same operation.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
	.remove(b'-')
	.remove(b'_')
	.remove(b'.')
	.remove(b'!')
	.remove(b'~')
	.remove(b'*')
	.remove(b'\'')
	.remove(b'(')
	.remove(b')');

/// An operation endpoint advertised in service metadata, e.g.
/// `https://anchor.example/api/getCertificates/{id}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
	template: String,
}

impl Endpoint {
	/// Substitute each `{key}` with its percent-encoded value and parse the
	/// result as an absolute URL.
	///
	/// # Errors
	///
	/// Returns [`AnchorClientError::Url`] when the filled template is not a
	/// valid absolute URL.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_anchor_client::service::Endpoint;
	///
	/// let endpoint = Endpoint::from("https://anchor.example/v/{id}");
	/// let url = endpoint.url(&[("id", "ver 1")])?;
	/// assert_eq!(url.as_str(), "https://anchor.example/v/ver%201");
	/// # Ok::<(), keetanetwork_anchor_client::AnchorClientError>(())
	/// ```
	pub fn url(&self, params: &[(&str, &str)]) -> Result<Url, AnchorClientError> {
		let mut filled = self.template.clone();
		for (key, value) in params {
			let placeholder = alloc::format!("{{{key}}}");
			let encoded = utf8_percent_encode(value, COMPONENT).to_string();
			filled = filled.replace(&placeholder, &encoded);
		}

		let url = Url::parse(&filled)?;
		Ok(url)
	}
}

impl From<String> for Endpoint {
	fn from(template: String) -> Self {
		Self { template }
	}
}

impl From<&str> for Endpoint {
	fn from(template: &str) -> Self {
		Self { template: template.to_string() }
	}
}
