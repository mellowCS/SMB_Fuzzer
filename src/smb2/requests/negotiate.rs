//! This module implements a SMB2 negotiate request
//! The SMB2 NEGOTIATE Request packet is used by the client to notify the server what dialects of the SMB 2 Protocol the client understands.
//! This request is composed of an SMB2 header, followed by this request structure.

use crate::smb2::helper_functions::negotiate_context::NegotiateContext;

/// negotiate request size of 36 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x24\x00";

/// A struct that represents a negotiate request
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Negotiate {
    /// StructureSize (2 bytes): The client MUST set this field to 36,
    /// indicating the size of a NEGOTIATE request. This is not the size
    /// of the structure with a single dialect in the Dialects[] array.
    /// This value MUST be set regardless of the number of dialects or
    /// number of negotiate contexts sent.
    pub structure_size: Vec<u8>,
    /// DialectCount (2 bytes): The number of dialects that are contained
    /// in the Dialects[] array. This value MUST be greater than 0.
    pub dialect_count: Vec<u8>,
    /// SecurityMode (2 bytes): When set, indicates that security signatures are enabled on the client.
    /// The client MUST set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is not set,
    /// and MUST NOT set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set.
    /// The server MUST ignore this bit.
    pub security_mode: Vec<u8>,
    /// Reserved (2 bytes): The client MUST set this to 0, and
    /// the server SHOULD ignore it on receipt.
    pub reserved: Vec<u8>,
    /// Capabilities (4 bytes): If the client implements the SMB 3.x dialect family,
    /// the Capabilities field MUST be constructed. To have multiple capabilities, add up
    /// the individual hex values. e.g. all capabilities would be 0x0000007f
    /// Otherwise, this field MUST be set to 0.
    pub capabilities: Vec<u8>,
    /// ClientGuid (16 bytes): It MUST be a GUID (as specified in [MS-DTYP] section 2.3.4.2)
    /// generated by the client.
    pub client_guid: Vec<u8>,
    /// NegotiateContextOffset (4 bytes): The offset, in bytes, from the beginning
    /// of the SMB2 header to the first, 8-byte-aligned negotiate context in the NegotiateContextList.
    /// NOTE: This implementation focuses on the dialect 0x311 which does not use the Client Start Time field.
    pub negotiate_context_offset: Vec<u8>,
    /// NegotiateContextCount (2 bytes): The number of negotiate contexts in NegotiateContextList.
    /// NOTE: This implementation focuses on the dialect 0x311 which does not use the Client Start Time field.
    pub negotiate_context_count: Vec<u8>,
    /// Reserved2 (2 bytes): The client MUST set this to 0, and the server MUST ignore it on receipt.
    /// NOTE: This implementation focuses on the dialect 0x311 which does not use the Client Start Time field.
    pub reserved2: Vec<u8>,
    /// ClientStartTime (8 bytes): This field MUST NOT be used and MUST be reserved.
    /// The client MUST set this to 0, and the server MUST ignore it on receipt.
    /// NOTE: This implementation focuses on the dialects < 0x311.
    pub client_start_time: Vec<u8>,
    /// Dialects (variable): An array of one or more 16-bit integers specifying
    /// the supported dialect revision numbers. The array MUST contain at least one value.
    pub dialects: Vec<Vec<u8>>,
    /// Padding (variable): Optional padding between the end of the Dialects array and
    /// the first negotiate context in NegotiateContextList so that the first negotiate context is 8-byte aligned.
    pub padding: Vec<u8>,
    /// NegotiateContextList (variable): If the Dialects field contains 0x0311,
    /// then this field will contain an array of SMB2 NEGOTIATE_CONTEXTs.
    /// The first negotiate context in the list MUST appear at the byte offset indicated by the
    /// SMB2 NEGOTIATE request's NegotiateContextOffset field. Subsequent negotiate contexts MUST appear
    /// at the first 8-byte-aligned offset following the previous negotiate context.
    pub negotiate_context_list: Vec<NegotiateContext>,
}

impl Negotiate {
    pub fn default() -> Self {
        Negotiate {
            structure_size: STRUCTURE_SIZE.to_vec(),
            dialect_count: Vec::new(),
            security_mode: Vec::new(),
            reserved: vec![0; 2],
            capabilities: Vec::new(),
            client_guid: Vec::new(),
            negotiate_context_offset: Vec::new(),
            negotiate_context_count: Vec::new(),
            reserved2: vec![0; 2],
            client_start_time: Vec::new(),
            dialects: Vec::new(),
            padding: Vec::new(),
            negotiate_context_list: Vec::new(),
        }
    }
}

/// Represents all supported dialects
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Dialects {
    Smb202,
    Smb21,
    Smb30,
    Smb302,
    Smb311,
}

impl Dialects {
    /// Return the corresponding byte code (4 bytes) for each dialect.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Dialects::Smb202 => b"\x02\x02".to_vec(),
            Dialects::Smb21 => b"\x10\x02".to_vec(),
            Dialects::Smb30 => b"\x00\x03".to_vec(),
            Dialects::Smb302 => b"\x02\x03".to_vec(),
            Dialects::Smb311 => b"\x11\x03".to_vec(),
        }
    }

    /// Return the dialect array of all SMB2 dialects as a byte sequence.
    pub fn get_all_dialects() -> Vec<Vec<u8>> {
        vec![
            Dialects::Smb202.unpack_byte_code(),
            Dialects::Smb21.unpack_byte_code(),
            Dialects::Smb30.unpack_byte_code(),
            Dialects::Smb302.unpack_byte_code(),
            Dialects::Smb311.unpack_byte_code(),
        ]
    }
}

impl std::fmt::Display for Negotiate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f,
        "Negotiate Request: \n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}",
        self.structure_size, self.dialect_count, self.security_mode, self.reserved, self.capabilities, self.client_guid, self.negotiate_context_offset, self.negotiate_context_count,
    self.reserved2, self.client_start_time, self.dialects, self.padding, self.negotiate_context_list)
    }
}
