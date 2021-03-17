//! Provides fields for NTLMSSP

mod authenticate;
mod challenge;
mod negotiate;
pub mod negotiate_flags;

/// Signature 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
const SIGNATURE: &[u8; 8] = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    /// Signature (8 bytes): An 8-byte character array that MUST contain
    /// the ASCII string ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0').
    signature: Vec<u8>,
    /// MessageType (4 bytes): The MessageType field.
    message_type: Vec<u8>,
    /// Furthe fields of the NTLM message, which depend on the message type.
    message: Option<MessageType>,
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
    Negotiate,
    Challenge,
    Authenticate,
}

impl MessageType {
    /// Unpacks the byte code of NTLM message types.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            MessageType::Negotiate => b"\x00\x00\x00\x01".to_vec(),
            MessageType::Challenge => b"\x00\x00\x00\x02".to_vec(),
            MessageType::Authenticate => b"\x00\x00\x00\x03".to_vec(),
        }
    }
}
