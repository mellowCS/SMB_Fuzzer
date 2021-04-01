//! Provides fields for NTLMSSP

pub mod authenticate;
pub mod challenge;
pub mod negotiate_flags;

use authenticate::Authenticate;
use challenge::Challenge;

/// Signature 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
const SIGNATURE: &[u8; 8] = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00";

/// NTLMSSP header that contains information about the message type and the message itself.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    /// Signature (8 bytes): An 8-byte character array that MUST contain
    /// the ASCII string ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0').
    pub signature: Vec<u8>,
    /// MessageType (4 bytes): The MessageType field.
    pub message_type: Vec<u8>,
    /// Furthe fields of the NTLM message, which depend on the message type.
    pub message: Option<MessageType>,
}

impl Header {
    /// Creates a new header instance for the ntlmssp packet.
    pub fn default() -> Self {
        Header {
            signature: SIGNATURE.to_vec(),
            message_type: Vec::new(),
            message: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageType {
    Challenge(Challenge),
    Authenticate(Box<Authenticate>),
}

impl MessageType {
    /// Unpacks the byte code of NTLM message types.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            MessageType::Challenge(_) => b"\x02\x00\x00\x00".to_vec(),
            MessageType::Authenticate(_) => b"\x03\x00\x00\x00".to_vec(),
        }
    }

    /// Maps the byte code of an incoming response to the corresponding message type.
    pub fn map_byte_code_to_message_type(byte_code: Vec<u8>) -> MessageType {
        if let Some(code) = byte_code.get(0) {
            match code {
                2 => MessageType::Challenge(Challenge::default()),
                3 => MessageType::Authenticate(Box::new(Authenticate::default())),
                _ => panic!("Invalid message type for NTLMSSP."),
            }
        } else {
            panic!("Empty message type for NTLMSSP.")
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
    pub product_major_version: Vec<u8>,
    /// ProductMinorVersion (1 byte): An 8-bit unsigned integer that SHOULD
    /// contain the minor version number of the operating system in use.
    pub product_minor_version: Vec<u8>,
    /// ProductBuild (2 bytes): A 16-bit unsigned integer that contains
    /// the build number of the operating system in use.
    /// This field SHOULD be set to a 16-bit quantity that identifies
    /// the operating system build number.
    pub product_build: Vec<u8>,
    /// Reserved (3 bytes): A 24-bit data area that SHOULD be
    /// set to zero and MUST be ignored by the recipient.
    pub reserved: Vec<u8>,
    /// NTLMRevisionCurrent (1 byte): An 8-bit unsigned integer that
    /// contains a value indicating the current revision of the NTLMSSP in use.
    /// This field SHOULD contain the value 0x0F: Version 15 of the NTLMSSP is in use.
    pub ntlm_revision_current: Vec<u8>,
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DomainNameFields {
    /// DomainNameLen (2 bytes): A 16-bit unsigned integer that
    /// defines the size, in bytes, of DomainName in the Payload.
    pub domain_name_len: Vec<u8>,
    /// DomainNameMaxLen (2 bytes): A 16-bit unsigned integer that
    /// SHOULD be set to the value of DomainNameLen, and MUST be ignored on receipt.
    pub domain_name_max_len: Vec<u8>,
    /// DomainNameBufferOffset (4 bytes): A 32-bit unsigned integer that defines
    /// the offset, in bytes, from the beginning of the NEGOTIATE_MESSAGE to DomainName in Payload.
    pub domain_name_buffer_offset: Vec<u8>,
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
    pub workstation_len: Vec<u8>,
    /// WorkstationMaxLen (2 bytes): A 16-bit unsigned integer that
    /// SHOULD be set to the value of WorkstationLen and MUST be ignored on receipt.
    pub workstation_max_len: Vec<u8>,
    /// WorkstationBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset,
    /// in bytes, from the beginning of the NEGOTIATE_MESSAGE to WorkstationName in the Payload.
    pub workstation_buffer_offset: Vec<u8>,
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

/// The AV_PAIR structure defines an attribute/value pair. Sequences of AV_PAIR structures
/// are used in the CHALLENGE_MESSAGE directly. They are also in the AUTHENTICATE_MESSAGE
/// via the NTLMv2_CLIENT_CHALLENGE structure.
/// When AV pairs are specified, MsvAvEOL MUST be the last item specified.
/// All other AV pairs, if present, can be specified in any order.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AVPair {
    /// AvId (2 bytes): A 16-bit unsigned integer that defines the information
    /// type in the Value field. The contents of this field MUST be a value from
    /// the following table. The corresponding Value field in this AV_PAIR MUST
    /// contain the information specified in the description of that AvId.
    pub av_id: Option<AvId>,
    /// AvLen (2 bytes): A 16-bit unsigned integer that defines the length,
    /// in bytes, of the Value field.
    pub av_len: Vec<u8>,
    /// Value (variable): A variable-length byte-array that contains the value
    /// defined for this AV pair entry. The contents of this field depend on the
    /// type expressed in the AvId field. The available types and resulting format
    /// and contents of this field are specified in the table within the AvId field
    /// description in this topic.
    pub value: Vec<u8>,
}

impl AVPair {
    /// Creates a new AV pair instance.
    pub fn default() -> Self {
        AVPair {
            av_id: None,
            av_len: Vec::new(),
            value: Vec::new(),
        }
    }
}

/// *MsvAvEOL*:
/// - Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0.
///   This type of information MUST be present in the AV pair list.
///
/// *MsvAvNbComputerName*:
/// - The server's NetBIOS computer name. The name MUST be in Unicode, and is
///   not null-terminated. This type of information MUST be present in the AV_pair list.
///
/// *MsvAvNbDomainName*:
/// - The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated.
///   This type of information MUST be present in the AV_pair list.
///
/// *MsvAvDnsComputerName*:
/// - The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode,
///   and is not null-terminated.
///
/// *MsvAvDnsDomainName*:
/// - The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
///
/// *MsvAvDnsTreeName*:
/// - The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated
///
/// *MsvAvFlags*:
/// - A 32-bit value indicating server or client configuration.
///     - 0x00000001: Indicates to the client that the account authentication is constrained.
///     - 0x00000002: Indicates that the client is providing message integrity in the MIC field
///       in the AUTHENTICATE_MESSAGE.
///     - 0x00000004: Indicates that the client is providing a target SPN generated from an untrusted source.
///
/// *MsvAvTimeStamp*:
/// - A FILETIME structure in little-endian byte order that contains the server local time.
///   This structure is always sent in the CHALLENGE_MESSAGE.
///
/// *MsvAvSingleHost*:
/// - A Single_Host_Data structure. The Value field contains a platform-specific blob,
///   as well as a MachineID created at computer startup to identify the calling machine.
///
/// *MsvAvTargetName*:
/// - The SPN of the target server. The name MUST be in Unicode and is not null-terminated.
///
/// *MsvAvChannelBindings*:
/// - A channel bindings hash. The Value field contains an MD5 hash of a gss_channel_bindings_struct.
///   An all-zero value of the hash is used to indicate absence of channel bindings.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AvId {
    MsvAvEOL,
    MsvAvNbComputerName,
    MsvAvNbDomainName,
    MsvAvDnsComputerName,
    MsvAvDnsDomainName,
    MsvAvDnsTreeName,
    MsvAvFlags,
    MsvAvTimeStamp,
    MsvAvSingleHost,
    MsvAvTargetName,
    MsvAvChannelBindings,
}

impl AvId {
    /// Unpacks the byte code of AV Ids.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            AvId::MsvAvEOL => b"\x00\x00".to_vec(),
            AvId::MsvAvNbComputerName => b"\x01\x00".to_vec(),
            AvId::MsvAvNbDomainName => b"\x02\x00".to_vec(),
            AvId::MsvAvDnsComputerName => b"\x03\x00".to_vec(),
            AvId::MsvAvDnsDomainName => b"\x04\x00".to_vec(),
            AvId::MsvAvDnsTreeName => b"\x05\x00".to_vec(),
            AvId::MsvAvFlags => b"\x06\x00".to_vec(),
            AvId::MsvAvTimeStamp => b"\x07\x00".to_vec(),
            AvId::MsvAvSingleHost => b"\x08\x00".to_vec(),
            AvId::MsvAvTargetName => b"\x09\x00".to_vec(),
            AvId::MsvAvChannelBindings => b"\x0a\x00".to_vec(),
        }
    }

    /// Maps the byte code of an incoming response to the corresponding AV ID.
    pub fn map_byte_code_to_av_id(byte_code: Vec<u8>) -> AvId {
        if let Some(code) = byte_code.get(0) {
            match code {
                0 => AvId::MsvAvEOL,
                1 => AvId::MsvAvNbComputerName,
                2 => AvId::MsvAvNbDomainName,
                3 => AvId::MsvAvDnsComputerName,
                4 => AvId::MsvAvDnsDomainName,
                5 => AvId::MsvAvDnsTreeName,
                6 => AvId::MsvAvFlags,
                7 => AvId::MsvAvTimeStamp,
                8 => AvId::MsvAvSingleHost,
                9 => AvId::MsvAvTargetName,
                10 => AvId::MsvAvChannelBindings,
                _ => panic!("Invalid AV ID."),
            }
        } else {
            panic!("Empty AV ID field.");
        }
    }
}
