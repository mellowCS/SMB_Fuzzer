//! The NEGOTIATE_MESSAGE defines an NTLM negotiate message that is sent from the client to the server.
//! This message allows the client to specify its supported NTLM options to the server.

use super::{DomainNameFields, Version, WorkstationFields};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Negotiate {
    /// NegotiateFlags (4 bytes): A NEGOTIATE structure that contains a set of flags.
    /// The client sets flags to indicate options it supports.
    /// The values for the negotiate flags should be taken from the Corresponding bitflag struct.
    negotiate_flags: Vec<u8>,
    /// DomainNameFields (8 bytes): A field containing DomainName information.
    /// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is set in NegotiateFlags,
    /// indicating that a DomainName is supplied in the Payload, the field is set.
    ///
    /// Otherwise, if the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
    /// indicating that a DomainName is not supplied in the Payload,
    /// DomainNameLen and DomainNameMaxLen fields SHOULD be set to zero.
    /// DomainNameBufferOffset field SHOULD be set to the offset from the beginning
    /// of the NEGOTIATE_MESSAGE to where the DomainName would be in Payload if it were present.
    domain_name_fields: DomainNameFields,
    /// WorkstationFields (8 bytes): A field containing WorkstationName information.
    /// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is set in NegotiateFlags,
    /// indicating that a WorkstationName is supplied in the Payload, the field should be set.
    ///
    /// Otherwise, if the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
    /// indicating that a WorkstationName is not supplied in the Payload,
    /// the fields take the following values, and MUST be ignored upon receipt.
    /// WorkstationLen and WorkstationMaxLen fields SHOULD be set to zero.
    /// WorkstationBufferOffset field SHOULD be set to the offset from the beginning of the
    /// NEGOTIATE_MESSAGE to where the WorkstationName would be in Payload if it were present.
    workstation_fields: WorkstationFields,
    /// Version (8 bytes): A VERSION structure that is populated only when the NTLMSSP_NEGOTIATE_VERSION
    /// flag is set in the NegotiateFlags field. This structure SHOULD be used for debugging purposes only.
    /// In normal (nondebugging) protocol messages, it is ignored and does not affect the NTLM message processing.
    version: Version,
    /// Payload (variable): A byte-array that contains the data referred to by the DomainNameBufferOffset and
    /// WorkstationBufferOffset fields. Payload data can be present in any order within the Payload field,
    /// with variable-length padding before or after the data. The data that can be present in the Payload
    /// field of this message, in no particular order.
    payload: Payload,
}

impl Negotiate {
    /// Creates a new instance of the negotiate message type for NTLMSSP.
    pub fn _default() -> Self {
        Negotiate {
            negotiate_flags: Vec::new(),
            domain_name_fields: DomainNameFields::default(),
            workstation_fields: WorkstationFields::default(),
            version: Version::default(),
            payload: Payload::_default(),
        }
    }
}

/// Payload (variable): A byte-array that contains the data referred to by the DomainNameBufferOffset and
/// WorkstationBufferOffset fields. Payload data can be present in any order within the Payload field,
/// with variable-length padding before or after the data. The data that can be present in the Payload
/// field of this message, in no particular order.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Payload {
    /// DomainName (variable): If DomainNameLen does not equal 0x0000, DomainName MUST be a byte-array that
    /// contains the name of the client authentication domain that MUST be encoded using the OEM character set.
    /// Otherwise, this data is not present.
    domain_name: Vec<u8>,
    /// WorkstationName (variable): If WorkstationLen does not equal 0x0000, WorkstationName MUST be a byte array
    /// that contains the name of the client machine that MUST be encoded using the OEM character set.
    /// Otherwise, this data is not present.
    workstation_name: Vec<u8>,
}

impl Payload {
    /// Creates a new instance of the NTLM Negotiate Payload.
    pub fn _default() -> Self {
        Payload {
            domain_name: Vec::new(),
            workstation_name: Vec::new(),
        }
    }
}
