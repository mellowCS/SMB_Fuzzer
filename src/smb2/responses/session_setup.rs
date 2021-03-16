//! This module implements the session setup response.
//! The SMB2 SESSION_SETUP Response packet is sent by the server in response to an SMB2 SESSION_SETUP Request packet.
//! This response is composed of an SMB2 header that is followed by this response structure:

/// session setup request size of 25 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x09\x00";

/// The SMB2 SESSION_SETUP Response packet is sent by the server in response to an SMB2 SESSION_SETUP Request packet.
/// This response is composed of an SMB2 header, that is followed by this response structure.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionSetup {
    /// StructureSize (2 bytes): The server MUST set this to 9,
    /// indicating the size of the fixed part of the response structure not including the header.
    /// The server MUST set it to this value regardless of how long Buffer[] actually is in the response.
    structure_size: Vec<u8>,
    /// SessionFlags (2 bytes): A flags field that indicates additional information about the session.
    /// This field MUST contain either 0 or one of the session flags.
    session_flags: Option<SessionFlags>,
    /// SecurityBufferOffset (2 bytes): The offset, in bytes, from the beginning of the
    /// SMB 2 Protocol header to the security buffer.
    security_buffer_offset: Vec<u8>,
    /// SecurityBufferLength (2 bytes): The length, in bytes, of the security buffer.
    security_buffer_length: Vec<u8>,
    /// Buffer (variable): A variable-length buffer that contains the security buffer for the response,
    /// as specified by SecurityBufferOffset and SecurityBufferLength.
    /// If the server initiated authentication using SPNEGO, the buffer MUST contain a token as produced
    /// by the GSS protocol. If the client initiated authentication, the buffer SHOULD contain a token
    /// as produced by an authentication protocol of the client's choice.
    buffer: Vec<u8>,
}

impl SessionSetup {
    /// Creat a new Session Setup instance.
    pub fn default() -> Self {
        SessionSetup {
            structure_size: STRUCTURE_SIZE.to_vec(),
            session_flags: None,
            security_buffer_offset: Vec::new(),
            security_buffer_length: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SessionFlags {
    IsGuest,
    IsNull,
    EncryptData,
    Zero,
}

impl SessionFlags {
    /// Unpack the byte code of session flags.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            SessionFlags::IsGuest => b"\x00\x01".to_vec(),
            SessionFlags::IsNull => b"\x00\x02".to_vec(),
            SessionFlags::EncryptData => b"\x00\x04".to_vec(),
            SessionFlags::Zero => b"\x00\x00".to_vec(),
        }
    }
}
