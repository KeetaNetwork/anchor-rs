use crate::asn1::{oids, error::AnchorAsn1Error};
use crate::generated::{Attribute, AttributeValue};
use keetanetwork_asn1::generated::iso20022::*;
use rasn::types::OctetString;

impl TryFrom<Address> for Attribute {
	type Error = AnchorAsn1Error;

	fn try_from(value: Address) -> Result<Self, Self::Error> {
		let name = oids::keeta::ADDRESS;
		let encoded = rasn::der::encode(&value)?;
		let value = AttributeValue::sensitiveValue(OctetString::from_slice(&encoded));
		Ok(Attribute { name, value })
	}
}

impl TryFrom<ContactDetails> for Attribute {
	type Error = AnchorAsn1Error;

	fn try_from(value: ContactDetails) -> Result<Self, Self::Error> {
		let name = oids::keeta::CONTACT_DETAILS;
		let encoded = rasn::der::encode(&value)?;
		let value = AttributeValue::sensitiveValue(OctetString::from_slice(&encoded));
		Ok(Attribute { name, value })
	}
}

impl TryFrom<DateAndPlaceOfBirth> for Attribute {
	type Error = AnchorAsn1Error;

	fn try_from(value: DateAndPlaceOfBirth) -> Result<Self, Self::Error> {
		let name = oids::keeta::DATE_AND_PLACE_OF_BIRTH;
		let encoded = rasn::der::encode(&value)?;
		let value = AttributeValue::sensitiveValue(OctetString::from_slice(&encoded));
		Ok(Attribute { name, value })
	}
}

impl TryFrom<Document> for Attribute {
	type Error = AnchorAsn1Error;

	fn try_from(value: Document) -> Result<Self, Self::Error> {
		let name = oids::keeta::DOCUMENT;
		let encoded = rasn::der::encode(&value)?;
		let value = AttributeValue::sensitiveValue(OctetString::from_slice(&encoded));
		Ok(Attribute { name, value })
	}
}

impl TryFrom<EntityType> for Attribute {
	type Error = AnchorAsn1Error;

	fn try_from(value: EntityType) -> Result<Self, Self::Error> {
		let name = oids::keeta::ENTITY_TYPE;
		let encoded = rasn::der::encode(&value)?;
		let value = AttributeValue::sensitiveValue(OctetString::from_slice(&encoded));
		Ok(Attribute { name, value })
	}
}

