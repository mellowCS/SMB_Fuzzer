//! This module implements the session setup response.

/// session setup request size of 25 bytes
const STRUCTURE_SIZE: &str = "0900";

/// The SMB2 SESSION_SETUP Response packet is sent by the server in response to an SMB2 SESSION_SETUP Request packet.
/// This response is composed of an SMB2 header, that is followed by this response structure.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionSetup {
    /// StructureSize (2 bytes): The server MUST set this to 9,
    /// indicating the size of the fixed part of the response structure not including the header.
    /// The server MUST set it to this value regardless of how long Buffer[] actually is in the response.
    structure_size: String,
    /// SessionFlags (2 bytes): A flags field that indicates additional information about the session.
    /// This field MUST contain either 0 or one of the session flags.
    session_flags: SessionFlags,
    /// SecurityBufferOffset (2 bytes): The offset, in bytes, from the beginning of the
    /// SMB 2 Protocol header to the security buffer.
    security_buffer_offset: String,
    /// SecurityBufferLength (2 bytes): The length, in bytes, of the security buffer.
    security_buffer_length: String,
    /// Buffer (variable): A variable-length buffer that contains the security buffer for the response,
    /// as specified by SecurityBufferOffset and SecurityBufferLength.
    /// If the server initiated authentication using SPNEGO, the buffer MUST contain a token as produced
    /// by the GSS protocol. If the client initiated authentication, the buffer SHOULD contain a token
    /// as produced by an authentication protocol of the client's choice.
    buffer: String,
}

impl SessionSetup {
    /// Creat a new Session Setup instance.
    pub fn new(session_flags: SessionFlags) -> Self {
        SessionSetup {
            structure_size: String::from(STRUCTURE_SIZE),
            session_flags,
            security_buffer_offset: String::new(),
            security_buffer_length: String::new(),
            buffer: String::new(),
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
    pub fn unpack_byte_code(&self) -> String {
        match self {
            SessionFlags::IsGuest => String::from("0001"),
            SessionFlags::IsNull => String::from("0002"),
            SessionFlags::EncryptData => String::from("0004"),
            SessionFlags::Zero => String::from("0000"),
        }
    }
}
