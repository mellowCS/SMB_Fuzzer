use super::Header;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Negotiate {
    header: Header,
    /// NegotiateFlags (4 bytes): A NEGOTIATE structure that contains a set of flags.
    /// The client sets flags to indicate options it supports.
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
    /// DomainName (variable): If DomainNameLen does not equal 0x0000, DomainName MUST be a byte-array that
    /// contains the name of the client authentication domain that MUST be encoded using the OEM character set.
    /// Otherwise, this data is not present.
    domain_name: Vec<u8>,
    /// WorkstationName (variable): If WorkstationLen does not equal 0x0000, WorkstationName MUST be a byte array
    /// that contains the name of the client machine that MUST be encoded using the OEM character set.
    /// Otherwise, this data is not present.
    workstation_name: Vec<u8>,
}

impl Negotiate {
    /// Creates a new instance of the negotiate message type for NTLMSSP.
    pub fn default() -> Self {
        Negotiate {
            header: Header::default(),
            negotiate_flags: Vec::new(),
            domain_name_fields: DomainNameFields::default(),
            workstation_fields: WorkstationFields::default(),
            version: Version::default(),
            domain_name: Vec::new(),
            workstation_name: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DomainNameFields {
    /// DomainNameLen (2 bytes): A 16-bit unsigned integer that
    /// defines the size, in bytes, of DomainName in the Payload.
    domain_name_len: Vec<u8>,
    /// DomainNameMaxLen (2 bytes): A 16-bit unsigned integer that
    /// SHOULD be set to the value of DomainNameLen, and MUST be ignored on receipt.
    domain_name_max_len: Vec<u8>,
    /// DomainNameBufferOffset (4 bytes): A 32-bit unsigned integer that defines
    /// the offset, in bytes, from the beginning of the NEGOTIATE_MESSAGE to DomainName in Payload.
    domain_name_buffer_offset: Vec<u8>,
}

impl DomainNameFields {
    /// Creates a new instance of the Domain Name Fields.
    pub fn default() -> Self {
        DomainNameFields {
            domain_name_len: Vec::new(),
            domain_name_max_len: Vec::new(),
            domain_name_buffer_offset: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WorkstationFields {
    /// WorkstationLen (2 bytes): A 16-bit unsigned integer that defines the size,
    /// in bytes, of WorkStationName in the Payload.
    workstation_len: Vec<u8>,
    /// WorkstationMaxLen (2 bytes): A 16-bit unsigned integer that
    /// SHOULD be set to the value of WorkstationLen and MUST be ignored on receipt.
    workstation_max_len: Vec<u8>,
    /// WorkstationBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset,
    /// in bytes, from the beginning of the NEGOTIATE_MESSAGE to WorkstationName in the Payload.
    workstation_buffer_offset: Vec<u8>,
}

impl WorkstationFields {
    /// Creates a new instance of the Workstation Fields.
    pub fn default() -> Self {
        WorkstationFields {
            workstation_len: Vec::new(),
            workstation_max_len: Vec::new(),
            workstation_buffer_offset: Vec::new(),
        }
    }
}

/// The VERSION structure contains operating system version information that SHOULD be ignored.
/// This structure is used for debugging purposes only and its value does not affect NTLM message processing.
/// It is populated in the NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE messages
/// only if NTLMSSP_NEGOTIATE_VERSION is negotiated.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Version {
    /// ProductMajorVersion (1 byte): An 8-bit unsigned integer that SHOULD
    /// contain the major version number of the operating system in use.
    product_major_version: Vec<u8>,
    /// ProductMinorVersion (1 byte): An 8-bit unsigned integer that SHOULD
    /// contain the minor version number of the operating system in use.
    product_minor_version: Vec<u8>,
    /// ProductBuild (2 bytes): A 16-bit unsigned integer that contains
    /// the build number of the operating system in use.
    /// This field SHOULD be set to a 16-bit quantity that identifies
    /// the operating system build number.
    product_build: Vec<u8>,
    /// Reserved (3 bytes): A 24-bit data area that SHOULD be
    /// set to zero and MUST be ignored by the recipient.
    reserved: Vec<u8>,
    /// NTLMRevisionCurrent (1 byte): An 8-bit unsigned integer that
    /// contains a value indicating the current revision of the NTLMSSP in use.
    /// This field SHOULD contain the value 0x0F: Version 15 of the NTLMSSP is in use.
    ntlm_revision_current: Vec<u8>,
}

impl Version {
    /// Creates a new instance of the NTLMSSP Version.
    pub fn default() -> Self {
        Version {
            product_major_version: Vec::new(),
            product_minor_version: Vec::new(),
            product_build: Vec::new(),
            reserved: b"\x00\x00\x00".to_vec(),
            ntlm_revision_current: Vec::new(),
        }
    }
}
