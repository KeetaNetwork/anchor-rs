//! The node client for the P1 core module, over the host fetch import.
//!
//! P1 has no `wasi:http`, so the node client's [`NodeTransport`] is
//! implemented on the same host shim the anchor HTTP transport uses. Only the
//! ledger reads the anchor client performs (`account_state`, `certificates`)
//! are wired; every other node operation reports a typed unsupported error.

use core::str::FromStr;
use core::time::Duration;

use std::sync::Arc;

use async_trait::async_trait;
use keetanetwork_account::GenericAccount;
use keetanetwork_anchor_client::keetanetwork_client::{
	AccountInfo, AccountState, Acl, BoxFuture, Certificate, ChainPage, ChainQuery, ClientConfig, ClientError,
	HistoryPage, HistoryQuery, KeetaClient, LedgerChecksum, LedgerSide, NodeTransport, RepPart, Representative,
	Runtime, TaskHandle, TokenBalance, TransportFactory, Vote, VoteQuote, VoteStaple,
};
use keetanetwork_anchor_client::AnchorHttpTransport;
use keetanetwork_block::{Amount, Block, BlockHash, BlockTime};
use num_bigint::BigInt;
use serde::Deserialize;
use snafu::Snafu;

use super::transport::{host_sleep_ms, monotonic_millis, unix_millis, HostTransport};

/// Failures specific to the host-backed node transport, boxed into
/// [`ClientError::Transport`] so the client's error surface stays uniform.
#[derive(Debug, Snafu)]
enum HostNodeError {
	/// The node answered with a non-success HTTP status.
	#[snafu(display("node request failed with status {status}"))]
	Status {
		/// The HTTP status the node returned.
		status: u16,
	},

	/// The operation is not implemented by the P1 host-backed transport.
	#[snafu(display("`{method}` is not supported by the P1 host node transport"))]
	Unsupported {
		/// The transport method that was invoked.
		method: &'static str,
	},
}

impl From<HostNodeError> for ClientError {
	fn from(error: HostNodeError) -> Self {
		Self::Transport { source: Box::new(error) }
	}
}

/// The node's account-state response shape. The client's generated OpenAPI
/// types require its `std` build, which P1 cannot enable (it would pull the
/// tokio/reqwest backend), so the two reads P1 performs decode locally.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountStateResponse {
	#[serde(default)]
	representative: Option<String>,
	#[serde(default)]
	current_head_block: Option<String>,
	#[serde(default)]
	current_head_block_height: Option<String>,
	#[serde(default)]
	info: Option<AccountInfoResponse>,
	#[serde(default)]
	balances: Vec<BalanceEntryResponse>,
}

/// The `info` object of an account-state response.
#[derive(Deserialize)]
struct AccountInfoResponse {
	#[serde(default)]
	name: Option<String>,
	#[serde(default)]
	description: Option<String>,
	#[serde(default)]
	metadata: Option<String>,
	#[serde(default)]
	supply: Option<String>,
}

/// One entry of an account-state `balances` array.
#[derive(Deserialize)]
struct BalanceEntryResponse {
	#[serde(default)]
	token: Option<String>,
	#[serde(default)]
	balance: Option<String>,
}

/// The node's account-certificates response shape.
#[derive(Deserialize)]
struct CertificatesResponse {
	#[serde(default)]
	certificates: Vec<CertificateRecordResponse>,
}

/// One published certificate record: the PEM leaf and its intermediates.
#[derive(Deserialize)]
struct CertificateRecordResponse {
	#[serde(default)]
	certificate: Option<String>,
	#[serde(default)]
	intermediates: Option<Vec<String>>,
}

/// A [`NodeTransport`] reading the node API at `base` through the host fetch
/// import. Only the ledger reads the anchor client needs are implemented.
#[derive(Debug)]
struct HostNodeTransport {
	/// The node API base URL, without a trailing `/`.
	base: String,
}

impl HostNodeTransport {
	/// A transport for the node API at `base`; a trailing `/` is ignored.
	fn new(base: &str) -> Self {
		Self { base: base.trim_end_matches('/').to_string() }
	}

	/// `GET {base}{path}` through the host shim, decoded as JSON.
	async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
		let url = format!("{}{path}", self.base);
		let response = HostTransport
			.get(&url)
			.await
			.map_err(|error| ClientError::Transport { source: Box::new(error) })?;

		if !response.is_success() {
			return Err(HostNodeError::Status { status: response.status }.into());
		}

		let decoded = serde_json::from_slice(&response.body);
		decoded.map_err(|error| ClientError::Transport { source: Box::new(error) })
	}
}

/// Parse an optional `0x`-hex amount, treating an absent field as zero.
fn decode_amount(value: Option<String>) -> Result<Amount, ClientError> {
	match value {
		None => Ok(Amount::default()),
		Some(value) => Amount::from_str(&value).map_err(|error| ClientError::Transport { source: Box::new(error) }),
	}
}

/// Parse a `keeta_…` address into the client's shared account reference.
fn decode_account(address: &str) -> Result<Arc<GenericAccount>, ClientError> {
	let account =
		GenericAccount::from_str(address).map_err(|error| ClientError::Transport { source: Box::new(error) })?;
	Ok(Arc::new(account))
}

/// Parse an optional hex block hash field, treating an absent field as `None`.
fn decode_hash(hash: Option<String>) -> Result<Option<BlockHash>, ClientError> {
	hash.map(|value| BlockHash::from_str(&value).map_err(|error| ClientError::Transport { source: Box::new(error) }))
		.transpose()
}

/// Assemble the client's [`AccountState`] from the response shape.
fn decode_account_state(state: AccountStateResponse) -> Result<AccountState, ClientError> {
	let supply = state
		.info
		.as_ref()
		.and_then(|info| info.supply.clone())
		.map(|supply| decode_amount(Some(supply)))
		.transpose()?;
	let height = state
		.current_head_block_height
		.map(|height| decode_amount(Some(height)))
		.transpose()?;
	let balances = state
		.balances
		.into_iter()
		.filter_map(|entry| {
			let token = entry.token?;
			let entry = decode_account(&token)
				.and_then(|token| decode_amount(entry.balance).map(|balance| TokenBalance { token, balance }));
			Some(entry)
		})
		.collect::<Result<Vec<_>, _>>()?;

	Ok(AccountState {
		representative: state
			.representative
			.as_deref()
			.map(decode_account)
			.transpose()?,
		head: decode_hash(state.current_head_block)?,
		height,
		info: state.info.map(|info| AccountInfo {
			name: info.name,
			description: info.description,
			metadata: info.metadata,
		}),
		supply,
		balances,
	})
}

/// Generate the [`NodeTransport`] impl: the two ledger reads the anchor
/// client performs, plus one typed [`HostNodeError::Unsupported`] method for
/// every other node operation. The whole impl is emitted here so `async_trait`
/// sees fully-expanded methods.
macro_rules! host_node_transport {
	(unsupported: $($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)+) => {
		#[async_trait(?Send)]
		impl NodeTransport for HostNodeTransport {
			async fn account_state(&self, account: &str) -> Result<AccountState, ClientError> {
				let path = format!("/node/ledger/account/{account}");
				let state: AccountStateResponse = self.get_json(&path).await?;
				decode_account_state(state)
			}

			async fn certificates(&self, account: &str) -> Result<Vec<Certificate>, ClientError> {
				let path = format!("/node/ledger/account/{account}/certificates");
				let response: CertificatesResponse = self.get_json(&path).await?;
				let records = response
					.certificates
					.into_iter()
					.filter_map(|record| {
						let certificate = record.certificate?;
						Some(Certificate { certificate, intermediates: record.intermediates.unwrap_or_default() })
					})
					.collect();

				Ok(records)
			}

			$(
				async fn $name(&self, $($arg: $ty),*) -> Result<$ret, ClientError> {
					$(let _ = $arg;)*
					Err(HostNodeError::Unsupported { method: stringify!($name) }.into())
				}
			)+
		}
	};
}

host_node_transport! {
	unsupported:
	node_version() -> String;
	balance(account: &str, token: &str) -> Amount;
	balances(account: &str) -> Vec<TokenBalance>;
	account_states(accounts: &[String]) -> Vec<AccountState>;
	head_block(account: &str) -> Option<Block>;
	account_head_info(account: &str) -> Option<(Block, Amount)>;
	pending_block(account: &str) -> Option<Block>;
	block(hash: BlockHash, side: Option<LedgerSide>) -> Option<Block>;
	successor_block(hash: BlockHash) -> Option<Block>;
	block_by_idempotent(account: &str, key: &str, side: Option<LedgerSide>) -> Option<Block>;
	block_votes(hash: BlockHash, side: LedgerSide) -> Option<Vec<Vote>>;
	chain_page(account: &str, query: &ChainQuery) -> ChainPage;
	history_page(account: &str, query: &HistoryQuery) -> HistoryPage;
	global_history_page(query: &HistoryQuery) -> HistoryPage;
	vote_staples_after(start: BlockTime, limit: Option<i64>) -> Vec<VoteStaple>;
	node_representative() -> Representative;
	representative(rep: &str) -> Representative;
	representatives() -> Vec<Representative>;
	ledger_checksum() -> LedgerChecksum;
	acls_by_principal(account: &str) -> Vec<Acl>;
	acls_by_entity(account: &str) -> Vec<Acl>;
	certificate(account: &str, hash: [u8; 32]) -> Option<Certificate>;
	create_vote(blocks: &[Block], prior: &[Vote], quote: Option<&VoteQuote>) -> Vote;
	create_vote_quote(blocks: &[Block]) -> VoteQuote;
	publish_staple(staple: &VoteStaple) -> bool;
}

/// Builds [`HostNodeTransport`]s for representatives bound at runtime.
#[derive(Clone, Copy, Debug, Default)]
struct HostNodeTransportFactory;

impl TransportFactory for HostNodeTransportFactory {
	fn create(&self, url: &str) -> Arc<dyn NodeTransport> {
		let transport = HostNodeTransport::new(url);

		Arc::new(transport)
	}
}

/// A detached-task handle for a runtime with no executor: there is nothing to
/// abort because nothing was spawned.
#[derive(Debug)]
struct HostNodeTask;

impl TaskHandle for HostNodeTask {
	fn abort(&self) {}
}

/// The node client's [`Runtime`] over the host sleep import and the wasip1
/// clocks. Background spawns are dropped: a single-representative client only
/// uses them for rep-set refresh, which never applies here.
#[derive(Debug, Default)]
struct HostNodeRuntime;

#[async_trait(?Send)]
impl Runtime for HostNodeRuntime {
	async fn sleep(&self, duration: Duration) {
		let requested = duration.as_millis();
		let millis = u64::try_from(requested).unwrap_or(u64::MAX);
		host_sleep_ms(millis);
	}

	fn spawn(&self, _future: BoxFuture) -> Box<dyn TaskHandle> {
		Box::new(HostNodeTask)
	}

	fn now_millis(&self) -> u64 {
		monotonic_millis()
	}

	fn unix_millis(&self) -> i64 {
		unix_millis()
	}
}

/// An anonymous single-representative node client targeting `node_url` over
/// the host fetch import, keyed by its URL (no account).
pub(super) fn node_client(node_url: &str) -> KeetaClient {
	let part = RepPart { key: node_url.to_owned(), url: node_url.to_owned(), weight: BigInt::from(1u8) };
	let factory = Arc::new(HostNodeTransportFactory);
	let runtime = Arc::new(HostNodeRuntime);
	let config = ClientConfig::default();

	KeetaClient::with_parts([part], factory, runtime, config, true)
}
