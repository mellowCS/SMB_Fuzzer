//! This file contains all necessary information needed to construct a SMB2 packet.

/// Protocol id with fixed value
const PROTOCOL_ID: &[u8; 4] = b"\xfe\x53\x4d\x42";
/// SMB head size of 64 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x40\x00";

/// All commands that could be in the command field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Commands {
    Negotiate,
    SessionSetup,
    Logoff,
    TreeConnect,
    TreeDisconnect,
    Create,
    Close,
    Flush,
    Read,
    Write,
    Lock,
    Ioctl,
    Cancel,
    Echo,
    QueryDirectory,
    ChangeNotify,
    QueryInfo,
    SetInfo,
    OplockBreak,
}

impl Commands {
    /// Return the corresponding byte code (2 bytes) for each command.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Commands::Negotiate => b"\x00\x00".to_vec(),
            Commands::SessionSetup => b"\x01\x00".to_vec(),
            Commands::Logoff => b"\x02\x00".to_vec(),
            Commands::TreeConnect => b"\x03\x00".to_vec(),
            Commands::TreeDisconnect => b"\x04\x00".to_vec(),
            Commands::Create => b"\x05\x00".to_vec(),
            Commands::Close => b"\x06\x00".to_vec(),
            Commands::Flush => b"\x07\x00".to_vec(),
            Commands::Read => b"\x08\x00".to_vec(),
            Commands::Write => b"\x09\x00".to_vec(),
            Commands::Lock => b"\x0a\x00".to_vec(),
            Commands::Ioctl => b"\x0b\x00".to_vec(),
            Commands::Cancel => b"\x0c\x00".to_vec(),
            Commands::Echo => b"\x0d\x00".to_vec(),
            Commands::QueryDirectory => b"\x0e\x00".to_vec(),
            Commands::ChangeNotify => b"\x0f\x00".to_vec(),
            Commands::QueryInfo => b"\x10\x00".to_vec(),
            Commands::SetInfo => b"\x11\x00".to_vec(),
            Commands::OplockBreak => b"\x12\x00".to_vec(),
        }
    }
}

/// The flags indicate how to process the operation. This field MUST be constructed using the following values:
///
/// *Server To Redir*:
///    - When set, indicates the message is response rather than a request.
///      This MUST be set on responses sent from the server to the client,
///      and MUST NOT be set on requests sent from the client to the server.
///
/// *Async Command*:
///    - When set, indicates that this is an ASYNC SMB2 header.
///
/// *Related Operations*:
///    - When set in an SMB2 request, indicates that this request is a related operation in a compounded request chain.
///    - When set in an SMB2 compound response, indicates that the request corresponding to this response was part of
///      a related operation in a compounded request chain.
///
/// *Signed*:
///    - When set, indicates that this packet has been signed.
///
/// *Priority Mask*:
///    - This flag is only valid for SMB 3.1.1 dialect. It is a mask for the requested I/O priority request, and
///      it MUST be a value in a range of 0 to 7.
///
/// *DFS Operations*:
///    - When set, indicates that this command is a Distributed File System (DFS) operation.
///
/// *Replay Operation*:
///    - This flag is only valid for the 3.x dialect family. When set, it indicates that this command is a replay operation.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Flags {
    ServerToRedir,
    AsyncCommand,
    RelatedOperations,
    Signed,
    PriorityMask,
    DFSOperations,
    ReplayOperation,
    NoFlags,
}

impl Flags {
    /// Return the corresponding byte code (4 bytes) for each flag.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Flags::ServerToRedir => b"\x01\x00\x00\x00".to_vec(),
            Flags::AsyncCommand => b"\x02\x00\x00\x00".to_vec(),
            Flags::RelatedOperations => b"\x04\x00\x00\x00".to_vec(),
            Flags::Signed => b"\x08\x00\x00\x00".to_vec(),
            Flags::PriorityMask => b"\x70\x00\x00\x00".to_vec(),
            Flags::DFSOperations => b"\x10\x00\x00\x00".to_vec(),
            Flags::ReplayOperation => b"\x20\x00\x00\x00".to_vec(),
            Flags::NoFlags => b"\x00\x00\x00\x00".to_vec(),
        }
    }
}

/// The SMB header struct contains all fields necessary to build a SMB header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GenericHeader {
    /// Protcol id (4 bytes) is constant over all SMB packets. It stands for 254 'S', 'M', 'B'
    pub protocol_id: Vec<u8>,
    /// Header length (2 bytes) must always be set to 64 bytes.
    pub structure_size: Vec<u8>,
    /// CreditCharge (2 bytes): In the SMB 2.0.2 dialect, this field MUST NOT be used and MUST be reserved.
    /// The sender MUST set this to 0, and the receiver MUST ignore it.
    /// In all other dialects, this field indicates the number of credits that this request consumes.
    pub credit_charge: Vec<u8>,
    /// ChannelSequence (2 bytes): This field is an indication to the server about the client's Channel change. Only for versions 3.x. (2 bytes)
    pub channel_sequence: Vec<u8>,
    /// Reserved (2 bytes): This field SHOULD be set to zero and the server MUST ignore it on receipt.
    /// In the SMB 2.0.2 and SMB 2.1 dialects, this field is interpreted as the Status field in a request.
    pub reserved: Vec<u8>,
    /// Status (4 bytes): The client MUST set this field to 0 and the server MUST ignore it on receipt.
    /// In all SMB dialects for a response this field is interpreted as the Status field.
    /// This field can be set to any value. Only for versions 2.x.
    pub status: Vec<u8>,
    /// Command (2 bytes): The command code of this packet. (2 bytes)
    pub command: Vec<u8>,
    /// CreditRequest/CreditResponse (2 bytes): On a request, this field indicates
    /// the number of credits the client is requesting.
    /// On a response, it indicates the number of credits granted to the client.
    pub credit: Vec<u8>,
    /// A flags field (4 bytes), which indicates how to process the operation.
    /// MUST be constructed using one of the Flag values.
    pub flags: Vec<u8>,
    /// NextCommand (4 bytes): For a compounded request and response, this field
    /// MUST be set to the offset, in bytes, from the beginning of this SMB2 header
    /// to the start of the subsequent 8-byte aligned SMB2 header.
    /// If this is not a compounded request or response,
    /// or this is the last header in a compounded request or response, this value MUST be 0.
    pub next_command: Vec<u8>,
    /// MessageId (8 bytes): A value that identifies a message request and
    /// response uniquely across all messages that are sent on the same SMB 2 Protocol transport connection.
    pub message_id: Vec<u8>,
}

impl GenericHeader {
    /// Creates a new generic header by setting the protocol id and structure size initially.
    pub fn default() -> Self {
        GenericHeader {
            protocol_id: PROTOCOL_ID.to_vec(),
            structure_size: STRUCTURE_SIZE.to_vec(),
            credit_charge: Vec::new(),
            channel_sequence: Vec::new(),
            reserved: Vec::new(),
            status: Vec::new(),
            command: Vec::new(),
            credit: Vec::new(),
            flags: Vec::new(),
            next_command: Vec::new(),
            message_id: Vec::new(),
        }
    }
}

impl std::fmt::Display for GenericHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Generic Header:\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}\n\t\t{:?}",
            self.protocol_id,
            self.structure_size,
            self.credit_charge,
            self.channel_sequence,
            self.reserved,
            self.status,
            self.command,
            self.credit,
            self.flags,
            self.next_command,
            self.message_id,
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// The SMB header for asynchronous messages.
pub struct AsyncHeader {
    /// Generic header fields that are equivalent for both sync and async headers.
    pub generic: GenericHeader,
    /// AsyncId (8 bytes): A unique identification number that is created by the server to handle operations asynchronously.
    pub async_id: Vec<u8>,
    /// SessionId (8 bytes): Uniquely identifies the established session for the command.
    ///This field MUST be set to 0 for an SMB2 NEGOTIATE Request and for an SMB2 NEGOTIATE Response.
    pub session_id: Vec<u8>,
    /// Signature (16 bytes): The 16-byte signature of the message,
    /// if SMB2_FLAGS_SIGNED is set in the Flags field of the SMB2 header and the message is not encrypted.
    /// If the message is not signed, this field MUST be 0.
    pub signature: Vec<u8>,
}

impl AsyncHeader {
    /// Creates a new async header by setting the protocol id and structure size initially.
    pub fn default() -> Self {
        AsyncHeader {
            generic: GenericHeader::default(),
            async_id: Vec::new(),
            session_id: Vec::new(),
            signature: Vec::new(),
        }
    }
}

impl std::fmt::Display for AsyncHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Async Header:\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}",
            self.generic, self.async_id, self.session_id, self.signature,
        )
    }
}

/// The SMB header for synchronous messages.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SyncHeader {
    /// Generic header fields that are equivalent for both sync and async headers.
    pub generic: GenericHeader,
    /// Reserved (4 bytes): The client SHOULD set this field to 0.
    /// The server MAY ignore this field on receipt.
    pub reserved: Vec<u8>,
    /// TreeId (4 bytes): Uniquely identifies the tree connect for the command.
    /// This MUST be 0 for the SMB2 TREE_CONNECT Request. The TreeId can be
    /// any unsigned 32-bit integer that is received from a previous SMB2 TREE_CONNECT Response.
    /// TreeId SHOULD be set to 0 for the following commands:
    /// - SMB2 NEGOTIATE Request
    /// - SMB2 NEGOTIATE Response
    /// - SMB2 SESSION_SETUP Request
    /// - SMB2 SESSION_SETUP Response
    /// - SMB2 LOGOFF Request
    /// - SMB2 LOGOFF Response
    /// - SMB2 ECHO Request
    /// - SMB2 ECHO Response
    /// - SMB2 CANCEL Request
    pub tree_id: Vec<u8>,
    /// SessionId (8 bytes): Uniquely identifies the established session for the command.
    /// This field MUST be set to 0 for an SMB2 NEGOTIATE Request and for an SMB2 NEGOTIATE Response.
    pub session_id: Vec<u8>,
    /// Signature (16 bytes): The 16-byte signature of the message, if SMB2_FLAGS_SIGNED
    /// is set in the Flags field of the SMB2 header and the message is not encrypted.
    /// If the message is not signed, this field MUST be 0.
    pub signature: Vec<u8>,
}

impl SyncHeader {
    /// Creates a new sync header by setting the protocol id and structure size initially.
    pub fn default() -> Self {
        SyncHeader {
            generic: GenericHeader::default(),
            reserved: b"\x00\x00\x00\x00".to_vec(),
            tree_id: Vec::new(),
            session_id: Vec::new(),
            signature: Vec::new(),
        }
    }
}

impl std::fmt::Display for SyncHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Sync Header: \n\t{}\n\t{:?}\n\t{:?}\n\t{:?}\n\t{:?}",
            self.generic, self.reserved, self.tree_id, self.session_id, self.signature,
        )
    }
}
