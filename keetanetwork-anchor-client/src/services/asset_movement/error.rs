//! Asset-movement domain outcomes: the typed blockers an anchor reports and the
//! account-status discriminant the client resolves.
//!
//! These are *data*, not client failures: a blocker describes what a user must
//! do before an operation can proceed (share KYC, complete a flow, grant a
//! permission). The client's own failures stay in
//! [`AnchorClientError`](crate::error::AnchorClientError). Each blocker is
//! parsed from the same `{ ok, name, code, data, error }` envelope every
//! `KeetaAnchorError` serializes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{json, Value};

/// A stable transport code identifying an asset-movement blocker.
const KYC_SHARE_NEEDED: &str = "KEETA_ANCHOR_ASSET_MOVEMENT_KYC_SHARE_NEEDED";
/// The additional-KYC-needed transport code.
const ADDITIONAL_KYC_NEEDED: &str = "KEETA_ANCHOR_ASSET_MOVEMENT_ADDITIONAL_KYC_NEEDED";
/// The operation-not-supported transport code.
const OPERATION_NOT_SUPPORTED: &str = "KEETA_ANCHOR_ASSET_MOVEMENT_OPERATION_NOT_SUPPORTED";
/// The user-action-needed transport code.
const USER_ACTION_NEEDED: &str = "KEETA_ANCHOR_ASSET_MOVEMENT_USER_ACTION_NEEDED";

/// A blocker an anchor reports that a user must resolve before proceeding.
///
/// Recognized codes rehydrate into their typed variant; any other error is kept
/// verbatim as [`Other`](Self::Other) so no information is lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetMovementBlocker {
	/// The user must share KYC attributes before proceeding.
	KycShareNeeded {
		/// An optional terms-of-service flow to complete first.
		tos_flow: Option<Value>,
		/// The attribute names the anchor needs, when specified.
		needed_attributes: Option<Vec<String>>,
		/// The principals the attributes must be shared with.
		share_with_principals: Vec<String>,
		/// Accepted issuer sets, each a list of `{ name, value }` entries.
		accepted_issuers: Value,
	},

	/// The user must complete additional KYC steps.
	AdditionalKycNeeded {
		/// The flow the user must complete, when specified.
		to_complete_flow: Option<Value>,
	},

	/// The requested operation is not supported for the given asset or rail.
	OperationNotSupported {
		/// The asset (or pair) the operation is unsupported for, canonicalized.
		for_asset: Option<Value>,
		/// The rail the operation is unsupported for.
		for_rail: Option<String>,
	},

	/// The user must take one or more on-ledger actions.
	UserActionNeeded {
		/// The actions to perform, each an opaque action descriptor.
		actions_needed: Vec<Value>,
	},

	/// Any other anchor error, kept verbatim.
	Other {
		/// The error class name.
		name: String,
		/// The programmatic error code, when present.
		code: Option<String>,
		/// The human-readable message.
		message: String,
	},
}

impl AssetMovementBlocker {
	/// The stable transport code identifying a recognized blocker variant.
	/// [`Other`](Self::Other) has no stable code of its own.
	pub fn transport_code(&self) -> Option<&'static str> {
		match self {
			Self::KycShareNeeded { .. } => Some(KYC_SHARE_NEEDED),
			Self::AdditionalKycNeeded { .. } => Some(ADDITIONAL_KYC_NEEDED),
			Self::OperationNotSupported { .. } => Some(OPERATION_NOT_SUPPORTED),
			Self::UserActionNeeded { .. } => Some(USER_ACTION_NEEDED),
			Self::Other { .. } => None,
		}
	}

	/// Whether the blocker rehydrated from a recognized asset-movement code.
	pub fn is_recognized(&self) -> bool {
		self.transport_code().is_some()
	}

	/// The `type`-discriminated JSON shape every FFI boundary emits.
	pub fn to_json(&self) -> Value {
		match self {
			Self::KycShareNeeded { tos_flow, needed_attributes, share_with_principals, accepted_issuers } => json!({
				"type": "kycShareNeeded",
				"tosFlow": tos_flow,
				"neededAttributes": needed_attributes,
				"shareWithPrincipals": share_with_principals,
				"acceptedIssuers": accepted_issuers,
			}),
			Self::AdditionalKycNeeded { to_complete_flow } => {
				json!({ "type": "additionalKycNeeded", "toCompleteFlow": to_complete_flow })
			}
			Self::OperationNotSupported { for_asset, for_rail } => {
				json!({ "type": "operationNotSupported", "forAsset": for_asset, "forRail": for_rail })
			}
			Self::UserActionNeeded { actions_needed } => {
				json!({ "type": "userActionNeeded", "actionsNeeded": actions_needed })
			}
			Self::Other { name, code, message } => {
				json!({ "type": "other", "name": name, "code": code, "message": message })
			}
		}
	}

	/// Rehydrate a blocker from an anchor error envelope
	/// (`{ ok, name, code, data, error }`).
	pub fn from_transport(entry: &Value) -> Self {
		let code = entry.get("code").and_then(Value::as_str);
		let data = entry.get("data");
		match code {
			Some(KYC_SHARE_NEEDED) => Self::kyc_share_needed(data),
			Some(ADDITIONAL_KYC_NEEDED) => {
				Self::AdditionalKycNeeded { to_complete_flow: field(data, "toCompleteFlow") }
			}
			Some(OPERATION_NOT_SUPPORTED) => Self::OperationNotSupported {
				for_asset: field(data, "forAsset"),
				for_rail: field(data, "forRail")
					.as_ref()
					.and_then(Value::as_str)
					.map(str::to_string),
			},
			Some(USER_ACTION_NEEDED) => Self::UserActionNeeded { actions_needed: array_field(data, "actionsNeeded") },
			_ => Self::other(entry, code),
		}
	}

	fn kyc_share_needed(data: Option<&Value>) -> Self {
		let needed_attributes = field(data, "neededAttributes")
			.as_ref()
			.and_then(Value::as_array)
			.map(|items| {
				items
					.iter()
					.filter_map(Value::as_str)
					.map(str::to_string)
					.collect()
			});
		let share_with_principals = array_field(data, "shareWithPrincipals")
			.iter()
			.filter_map(Value::as_str)
			.map(str::to_string)
			.collect();

		Self::KycShareNeeded {
			tos_flow: field(data, "tosFlow"),
			needed_attributes,
			share_with_principals,
			accepted_issuers: field(data, "acceptedIssuers").unwrap_or(Value::Null),
		}
	}

	fn other(entry: &Value, code: Option<&str>) -> Self {
		let name = entry
			.get("name")
			.and_then(Value::as_str)
			.unwrap_or_default()
			.to_string();
		let message = entry
			.get("error")
			.and_then(Value::as_str)
			.unwrap_or_default()
			.to_string();
		Self::Other { name, code: code.map(str::to_string), message }
	}
}

/// The account's readiness to use an asset-movement provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountStatus {
	/// The account is ready to proceed.
	Ready,

	/// The account must resolve one or more blockers first.
	ActionRequired {
		/// The blockers the account must resolve.
		blockers: Vec<AssetMovementBlocker>,
	},
}

/// Read a single field from an optional `data` object.
fn field(data: Option<&Value>, key: &str) -> Option<Value> {
	data.and_then(|data| data.get(key))
		.filter(|value| !value.is_null())
		.cloned()
}

/// Read an array field from an optional `data` object, defaulting to empty.
fn array_field(data: Option<&Value>, key: &str) -> Vec<Value> {
	field(data, key)
		.as_ref()
		.and_then(Value::as_array)
		.cloned()
		.unwrap_or_default()
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	#[test]
	fn a_kyc_share_blocker_rehydrates_its_principals_and_attributes() {
		let entry = json!({
			"ok": false,
			"name": "KeetaAssetMovementAnchorKYCShareNeededError",
			"code": KYC_SHARE_NEEDED,
			"data": {
				"tosFlow": null,
				"neededAttributes": ["fullName", "dateOfBirth"],
				"shareWithPrincipals": ["keeta_principal"],
				"acceptedIssuers": [[{ "name": "issuer", "value": "keeta_ca" }]]
			},
			"error": "share needed"
		});

		let blocker = AssetMovementBlocker::from_transport(&entry);
		assert_eq!(
			blocker,
			AssetMovementBlocker::KycShareNeeded {
				tos_flow: None,
				needed_attributes: Some(alloc::vec!["fullName".to_string(), "dateOfBirth".to_string()]),
				share_with_principals: alloc::vec!["keeta_principal".to_string()],
				accepted_issuers: json!([[{ "name": "issuer", "value": "keeta_ca" }]]),
			}
		);
	}

	#[test]
	fn an_operation_not_supported_blocker_reads_asset_and_rail() {
		let entry = json!({
			"code": OPERATION_NOT_SUPPORTED,
			"name": "n",
			"error": "e",
			"data": { "forAsset": "USD", "forRail": "KEETA_SEND" }
		});

		let blocker = AssetMovementBlocker::from_transport(&entry);
		assert_eq!(
			blocker,
			AssetMovementBlocker::OperationNotSupported {
				for_asset: Some(json!("USD")),
				for_rail: Some("KEETA_SEND".to_string()),
			}
		);
	}

	#[test]
	fn an_unknown_error_is_kept_verbatim() {
		let entry = json!({ "name": "SomeError", "code": "SOMETHING_ELSE", "error": "boom" });
		let blocker = AssetMovementBlocker::from_transport(&entry);
		assert_eq!(
			blocker,
			AssetMovementBlocker::Other {
				name: "SomeError".to_string(),
				code: Some("SOMETHING_ELSE".to_string()),
				message: "boom".to_string(),
			}
		);
	}

	#[test]
	fn a_recognized_blocker_reports_its_transport_code() {
		for code in [KYC_SHARE_NEEDED, ADDITIONAL_KYC_NEEDED, OPERATION_NOT_SUPPORTED, USER_ACTION_NEEDED] {
			let entry = json!({ "code": code, "name": "n", "error": "e", "data": {} });
			let blocker = AssetMovementBlocker::from_transport(&entry);
			assert_eq!(blocker.transport_code(), Some(code));
			assert!(blocker.is_recognized());
		}
	}

	#[test]
	fn an_unknown_blocker_has_no_transport_code() {
		let entry = json!({ "name": "SomeError", "code": "SOMETHING_ELSE", "error": "boom" });
		let blocker = AssetMovementBlocker::from_transport(&entry);
		assert_eq!(blocker.transport_code(), None);
		assert!(!blocker.is_recognized());
	}

	#[test]
	fn an_additional_kyc_blocker_rehydrates_its_flow() {
		let entry = json!({
			"code": ADDITIONAL_KYC_NEEDED,
			"name": "n",
			"error": "e",
			"data": { "toCompleteFlow": { "url": "https://flow" } }
		});

		let blocker = AssetMovementBlocker::from_transport(&entry);
		assert_eq!(
			blocker,
			AssetMovementBlocker::AdditionalKycNeeded { to_complete_flow: Some(json!({ "url": "https://flow" })) }
		);
	}

	#[test]
	fn a_user_action_blocker_rehydrates_its_actions() {
		let entry = json!({
			"code": USER_ACTION_NEEDED,
			"name": "n",
			"error": "e",
			"data": { "actionsNeeded": [{ "action": "setInfo" }] }
		});

		let blocker = AssetMovementBlocker::from_transport(&entry);
		assert_eq!(
			blocker,
			AssetMovementBlocker::UserActionNeeded { actions_needed: alloc::vec![json!({ "action": "setInfo" })] }
		);
	}

	#[test]
	fn every_variant_emits_its_type_discriminated_json() {
		let cases = [
			(
				AssetMovementBlocker::AdditionalKycNeeded { to_complete_flow: None },
				json!({ "type": "additionalKycNeeded", "toCompleteFlow": null }),
			),
			(
				AssetMovementBlocker::OperationNotSupported {
					for_asset: Some(json!("USD")),
					for_rail: Some("KEETA_SEND".to_string()),
				},
				json!({ "type": "operationNotSupported", "forAsset": "USD", "forRail": "KEETA_SEND" }),
			),
			(
				AssetMovementBlocker::UserActionNeeded { actions_needed: alloc::vec![json!({ "action": "setInfo" })] },
				json!({ "type": "userActionNeeded", "actionsNeeded": [{ "action": "setInfo" }] }),
			),
			(
				AssetMovementBlocker::Other {
					name: "SomeError".to_string(),
					code: Some("SOMETHING_ELSE".to_string()),
					message: "boom".to_string(),
				},
				json!({ "type": "other", "name": "SomeError", "code": "SOMETHING_ELSE", "message": "boom" }),
			),
		];

		for (blocker, expected) in cases {
			assert_eq!(blocker.to_json(), expected);
		}
	}

	#[test]
	fn to_json_round_trips_through_from_transport() {
		let entry = json!({
			"code": KYC_SHARE_NEEDED,
			"name": "n",
			"error": "e",
			"data": {
				"neededAttributes": ["fullName"],
				"shareWithPrincipals": ["keeta_principal"],
				"acceptedIssuers": []
			}
		});

		let blocker = AssetMovementBlocker::from_transport(&entry);
		assert_eq!(
			blocker.to_json(),
			json!({
				"type": "kycShareNeeded",
				"tosFlow": null,
				"neededAttributes": ["fullName"],
				"shareWithPrincipals": ["keeta_principal"],
				"acceptedIssuers": [],
			})
		);
	}
}
