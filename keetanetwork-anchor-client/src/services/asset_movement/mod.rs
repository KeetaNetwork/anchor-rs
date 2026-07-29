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
pub use client::{AssetMovementClient, AssetMovementProvider, AwaitOptions};
pub use error::{AccountStatus, AssetMovementBlocker};
pub use location::{canonicalize_location, AssetLocation, ChainLocation};
pub use metadata::{
	AnchorDetails, AssetMovementOperations, AssetMovementProviderInfo, AssetMovementQuery, ClientRenderableContent,
	Disclaimer, DisclaimerPurpose, EndpointAuth, OperationEndpoint, ProviderFilter, ProviderSearch,
	TokenLocationMetadata, OPERATION_NAMES,
};
pub use request::{
	CreatePersistentForwardingAddressRequest, CreatePersistentForwardingTemplateRequest, ExecuteTransferRequest,
	ForwardingAddressFilter, ForwardingDestination, InitiatePersistentForwardingTemplateRequest,
	ListForwardingAddressTemplatesRequest, ListForwardingAddressesRequest, ListTransactionsRequest, Pagination,
	PersistentAddressFilter, ShareKycRequest, TransactionEndpointFilter, TransactionRefFilter, TransferDestination,
	TransferRequest, TransferSource,
};
pub use response::{
	parse_total, AddressPage, AssetOrAssetWithLocation, FeeBreakdown, FeeLineItem, ForwardingAddress,
	ForwardingTemplate, MinimumTransferValue, ShareKycOutcome, SimulatedTransfer, TemplatePage, TemplateSession,
	TransactionPage, Transfer, TransferStatus,
};
