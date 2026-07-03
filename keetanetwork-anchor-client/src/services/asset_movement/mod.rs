//! Asset movement anchor client: discover providers, move value across chains
//! and rails, manage persistent forwarding, and share KYC attributes.

pub mod asset;
pub mod client;
pub mod error;
pub mod location;
pub mod metadata;
pub mod request;
pub mod response;

pub use asset::{canonicalize_asset, AssetOrPair};
pub use client::{AssetMovementClient, AwaitOptions};
pub use error::{AccountStatus, AssetMovementBlocker};
pub use location::{canonicalize_location, AssetLocation, ChainLocation};
pub use metadata::{
	AssetMovementOperations, AssetMovementProvider, AssetMovementQuery, ClientRenderableContent, Disclaimer,
	DisclaimerPurpose, EndpointAuth, OperationEndpoint, ProviderFilter, ProviderSearch, TokenLocationMetadata,
	OPERATION_NAMES,
};
pub use request::{
	CreatePersistentForwardingAddressRequest, CreatePersistentForwardingTemplateRequest, ExecuteTransferRequest,
	ForwardingAddressFilter, ForwardingDestination, InitiatePersistentForwardingTemplateRequest,
	ListForwardingAddressTemplatesRequest, ListForwardingAddressesRequest, ListTransactionsRequest, Pagination,
	PersistentAddressFilter, ShareKycRequest, TransactionEndpointFilter, TransactionRefFilter, TransferDestination,
	TransferRequest, TransferSource,
};
pub use response::{
	parse_total, AddressPage, ForwardingTemplate, ShareKycOutcome, SimulatedTransfer, TemplatePage, TemplateSession,
	TransactionPage, Transfer, TransferStatus,
};
