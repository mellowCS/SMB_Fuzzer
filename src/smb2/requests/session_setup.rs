//! This module implements the session setup request.

use crate::smb2::handshake_helper::fields::SecurityMode;

/// session setup request size of 25 bytes
const STRUCTURE_SIZE: &str = "1900";

/// The SMB2 SESSION_SETUP Request packet is sent by the client to request a
/// new authenticated session within a new or existing
/// SMB 2 Protocol transport connection to the server.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionSetup {
    /// StructureSize (2 bytes): The client MUST set this field to 25,
    /// indicating the size of the request structure, not including the header.
    /// The client MUST set it to this value regardless of how long Buffer[]
    /// actually is in the request being sent.
    structure_size: String,
    /// Flags (1 byte): If the client implements the SMB 3.x dialect family,
    /// this field MUST be set to combination of zero or more flags.
    /// Otherwise, it MUST be set to 0.
    flags: String,
    /// SecurityMode (1 byte): The security mode field specifies whether SMB signing
    /// is enabled or required at the client. This field MUST be set.
    security_mode: SecurityMode,
    /// Capabilities (4 bytes): Specifies protocol capabilities for the client.
    capabilities: String,
    /// Channel (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// The client MUST set this to 0, and the server MUST ignore it on receipt.
    channel: String,
    /// SecurityBufferOffset (2 bytes): The offset, in bytes, from the beginning of the
    /// SMB 2 Protocol header to the security buffer.
    security_buffer_offset: String,
    /// SecurityBufferLength (2 bytes): The length, in bytes, of the security buffer.
    security_buffer_length: String,
    /// PreviousSessionId (8 bytes): A previously established session identifier.
    /// The server uses this value to identify the client session that was disconnected due to a network error.
    previous_session_id: String,
    /// Buffer (variable): A variable-length buffer that contains the security buffer for the request,
    /// as specified by SecurityBufferOffset and SecurityBufferLength.
    /// If the server initiated authentication using SPNEGO, the buffer MUST contain a token as produced by
    /// the GSS protocol. If the client initiated authentication, the buffer SHOULD contain a token
    /// as produced by an authentication protocol of the client's choice.
    buffer: String,
}

impl SessionSetup {
    pub fn new(security_mode: SecurityMode) -> Self {
        SessionSetup {
            structure_size: String::from(STRUCTURE_SIZE),
            flags: String::new(),
            security_mode,
            capabilities: String::new(),
            channel: String::from("00000000"),
            security_buffer_offset: String::new(),
            security_buffer_length: String::new(),
            previous_session_id: String::new(),
            buffer: String::new(),
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
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            Flags::SessionSetupBinding => 0x01,
            Flags::Zero => 0x00,
        }
    }

    /// Adds all flags together.
    pub fn add_all_flags() -> String {
        let combined_flags = Flags::SessionSetupBinding.unpack_byte_code();
        format!("{:#4x}", combined_flags)
            .strip_prefix("0x")
            .unwrap()
            .to_string()
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
    pub fn unpack_byte_code(&self) -> String {
        match self {
            Capabilities::GlobalCapDFS => String::from("00000001"),
        }
    }
}
