//! This module implements the session setup request.
//! The SMB2 SESSION_SETUP Request packet is sent by the client to request a new authenticated session
//! within a new or existing SMB 2 Protocol transport connection to the server.
//! This request is composed of an SMB2 header, followed by this request structure.

/// session setup request size of 25 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x19\x00";

/// The SMB2 SESSION_SETUP Request packet is sent by the client to request a
/// new authenticated session within a new or existing
/// SMB 2 Protocol transport connection to the server.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionSetup {
    /// StructureSize (2 bytes): The client MUST set this field to 25,
    /// indicating the size of the request structure, not including the header.
    /// The client MUST set it to this value regardless of how long Buffer[]
    /// actually is in the request being sent.
    pub structure_size: Vec<u8>,
    /// Flags (1 byte): If the client implements the SMB 3.x dialect family,
    /// this field MUST be set to combination of zero or more flags.
    /// Otherwise, it MUST be set to 0.
    pub flags: Vec<u8>,
    /// SecurityMode (1 byte): The security mode field specifies whether SMB signing
    /// is enabled or required at the client. This field MUST be set.
    pub security_mode: Vec<u8>,
    /// Capabilities (4 bytes): Specifies protocol capabilities for the client.
    pub capabilities: Vec<u8>,
    /// Channel (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// The client MUST set this to 0, and the server MUST ignore it on receipt.
    pub channel: Vec<u8>,
    /// SecurityBufferOffset (2 bytes): The offset, in bytes, from the beginning of the
    /// SMB 2 Protocol header to the security buffer.
    pub security_buffer_offset: Vec<u8>,
    /// SecurityBufferLength (2 bytes): The length, in bytes, of the security buffer.
    pub security_buffer_length: Vec<u8>,
    /// PreviousSessionId (8 bytes): A previously established session identifier.
    /// The server uses this value to identify the client session that was disconnected due to a network error.
    pub previous_session_id: Vec<u8>,
    /// Buffer (variable): A variable-length buffer that contains the security buffer for the request,
    /// as specified by SecurityBufferOffset and SecurityBufferLength.
    /// If the server initiated authentication using SPNEGO, the buffer MUST contain a token as produced by
    /// the GSS protocol. If the client initiated authentication, the buffer SHOULD contain a token
    /// as produced by an authentication protocol of the client's choice.
    pub buffer: Vec<u8>,
}

impl SessionSetup {
    pub fn default() -> Self {
        SessionSetup {
            structure_size: STRUCTURE_SIZE.to_vec(),
            flags: Vec::new(),
            security_mode: Vec::new(),
            capabilities: Vec::new(),
            channel: b"\x00\x00\x00\x00".to_vec(),
            security_buffer_offset: Vec::new(),
            security_buffer_length: Vec::new(),
            previous_session_id: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

/// *Session Setup Binding*:
///     - When set, indicates that the request is to bind an existing session to a new connection.
///
/// *Zero*:
///     - Introduces an additional zero value if no flags are set.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Flags {
    SessionSetupBinding,
    Zero,
}

impl Flags {
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Flags::SessionSetupBinding => b"\x01".to_vec(),
            Flags::Zero => b"\x00".to_vec(),
        }
    }
}

/// *Global Cap DFS*:
///     - When set, indicates that the client supports the Distributed File System (DFS).
///
/// *Global Cap Unused1*:
///     - SHOULD be set to zero, and server MUST ignore.
///
/// *Global Cap Unused2*:
///     - SHOULD be set to zero, and server MUST ignore.
///
/// *Global Cap Unused3*:
///     - SHOULD be set to zero, and server MUST ignore.
///
/// Values other than those that are defined in the negotiation capabilities table
/// are unused at present and SHOULD be treated as reserved.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Capabilities {
    GlobalCapDFS,
}

impl Capabilities {
    /// Unpack the byte code of session setup capabilities.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Capabilities::GlobalCapDFS => b"\x00\x00\x00\x01".to_vec(),
        }
    }
}
