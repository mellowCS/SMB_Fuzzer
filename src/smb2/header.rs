//! This file contains all necessary information needed to construct a SMB2 packet.

/// Protocol id with fixed value
const PROTOCOL_ID: &str = "fe534d42";
/// SMB head size of 64 bytes
const STRUCTURE_SIZE: &str = "4000";

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
    pub fn unpack_byte_code(&self) -> String {
        match self {
            Commands::Negotiate => String::from("0000"),
            Commands::SessionSetup => String::from("0001"),
            Commands::Logoff => String::from("0002"),
            Commands::TreeConnect => String::from("0003"),
            Commands::TreeDisconnect => String::from("0004"),
            Commands::Create => String::from("0005"),
            Commands::Close => String::from("0006"),
            Commands::Flush => String::from("0007"),
            Commands::Read => String::from("0008"),
            Commands::Write => String::from("0009"),
            Commands::Lock => String::from("000a"),
            Commands::Ioctl => String::from("000b"),
            Commands::Cancel => String::from("000c"),
            Commands::Echo => String::from("000d"),
            Commands::QueryDirectory => String::from("000e"),
            Commands::ChangeNotify => String::from("000f"),
            Commands::QueryInfo => String::from("0010"),
            Commands::SetInfo => String::from("0011"),
            Commands::OplockBreak => String::from("0012"),
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
}

impl Flags {
    /// Return the corresponding byte code (4 bytes) for each flag.
    pub fn unpack_byte_code(&self) -> String {
        match self {
            Flags::ServerToRedir => String::from("00000001"),
            Flags::AsyncCommand => String::from("00000002"),
            Flags::RelatedOperations => String::from("00000004"),
            Flags::Signed => String::from("00000008"),
            Flags::PriorityMask => String::from("00000070"),
            Flags::DFSOperations => String::from("10000000"),
            Flags::ReplayOperation => String::from("20000000"),
        }
    }
}

/// The SMB header struct contains all fields necessary to build a SMB header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GenericHeader {
    /// Protcol id (4 bytes) is constant over all SMB packets. It stands for 254 'S', 'M', 'B'
    protocol_id: String,
    /// Header length (2 bytes) must always be set to 64 bytes.
    structure_size: String,
    /// In the SMB 2.0.2 dialect, this field MUST NOT be used and MUST be reserved.
    /// The sender MUST set this to 0, and the receiver MUST ignore it.
    /// In all other dialects, this field indicates the number of credits that this request consumes.
    credit_charge: Option<String>,
    /// This field is an indication to the server about the client's Channel change. Only for versions 3.x. (2 bytes)
    channel_sequence: Option<String>,
    /// This field SHOULD be set to zero and the server MUST ignore it on receipt.
    /// In the SMB 2.0.2 and SMB 2.1 dialects, this field is interpreted as the Status field in a request.
    reserved: Option<String>,
    /// The client MUST set this field to 0 and the server MUST ignore it on receipt.
    /// In all SMB dialects for a response this field is interpreted as the Status field.
    /// This field can be set to any value. Only for versions 2.x.
    status: Option<String>,
    /// The command code of this packet. (2 bytes)
    command: Option<String>,
    /// CreditRequest/CreditResponse (2 bytes): On a request, this field indicates
    /// the number of credits the client is requesting.
    /// On a response, it indicates the number of credits granted to the client.
    credit: Option<String>,
    /// A flags field (4 bytes), which indicates how to process the operation.
    /// MUST be constructed using one of the Flag values.
    flags: Vec<String>,
    /// NextCommand (4 bytes): For a compounded request and response, this field
    /// MUST be set to the offset, in bytes, from the beginning of this SMB2 header
    /// to the start of the subsequent 8-byte aligned SMB2 header.
    /// If this is not a compounded request or response,
    /// or this is the last header in a compounded request or response, this value MUST be 0.
    next_command: Option<String>,
    /// MessageId (8 bytes): A value that identifies a message request and
    /// response uniquely across all messages that are sent on the same SMB 2 Protocol transport connection.
    message_id: Option<String>,
}

impl GenericHeader {
    /// Creates a new generic header by setting the protocol id and structure size initially.
    pub fn default() -> Self {
        GenericHeader {
            protocol_id: PROTOCOL_ID.to_string(),
            structure_size: STRUCTURE_SIZE.to_string(),
            credit_charge: None,
            channel_sequence: None,
            reserved: None,
            status: None,
            command: None,
            credit: None,
            flags: Vec::new(),
            next_command: None,
            message_id: None,
        }
    }

    /// Prints optional fields even if they resolve to None.
    pub fn print_optional_string(field: Option<String>) -> String {
        match field {
            None => String::from("None"),
            Some(value) => value,
        }
    }
}

impl std::fmt::Display for GenericHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Generic Header:\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}",
            self.protocol_id,
            self.structure_size,
            GenericHeader::print_optional_string(self.credit_charge.clone()),
            GenericHeader::print_optional_string(self.channel_sequence.clone()),
            GenericHeader::print_optional_string(self.reserved.clone()),
            GenericHeader::print_optional_string(self.status.clone()),
            GenericHeader::print_optional_string(self.command.clone()),
            GenericHeader::print_optional_string(self.credit.clone()),
            self.flags.clone().into_iter().collect::<String>(),
            GenericHeader::print_optional_string(self.next_command.clone()),
            GenericHeader::print_optional_string(self.message_id.clone())
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// The SMB header for asynchronous messages.
pub struct AsyncHeader {
    /// Generic header fields that are equivalent for both sync and async headers.
    generic: GenericHeader,
    /// AsyncId (8 bytes): A unique identification number that is created by the server to handle operations asynchronously.
    async_id: Option<String>,
    /// SessionId (8 bytes): Uniquely identifies the established session for the command.
    ///This field MUST be set to 0 for an SMB2 NEGOTIATE Request and for an SMB2 NEGOTIATE Response.
    session_id: Option<String>,
    /// Signature (16 bytes): The 16-byte signature of the message,
    /// if SMB2_FLAGS_SIGNED is set in the Flags field of the SMB2 header and the message is not encrypted.
    /// If the message is not signed, this field MUST be 0.
    signature: Option<String>,
}

impl AsyncHeader {
    /// Creates a new async header by setting the protocol id and structure size initially.
    pub fn default() -> Self {
        AsyncHeader {
            generic: GenericHeader::default(),
            async_id: None,
            session_id: None,
            signature: None,
        }
    }
}

impl std::fmt::Display for AsyncHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Async Header:\n\t{}\n\t{}\n\t{}\n\t{}",
            self.generic,
            GenericHeader::print_optional_string(self.async_id.clone()),
            GenericHeader::print_optional_string(self.session_id.clone()),
            GenericHeader::print_optional_string(self.signature.clone()),
        )
    }
}

/// The SMB header for synchronous messages.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SyncHeader {
    /// Generic header fields that are equivalent for both sync and async headers.
    generic: GenericHeader,
    /// Reserved (8 bytes): The client SHOULD<2> set this field to 0.
    /// The server MAY<3> ignore this field on receipt.
    reserved: Option<String>,
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
    tree_id: Option<String>,
    /// SessionId (8 bytes): Uniquely identifies the established session for the command.
    /// This field MUST be set to 0 for an SMB2 NEGOTIATE Request and for an SMB2 NEGOTIATE Response.
    session_id: Option<String>,
    /// Signature (16 bytes): The 16-byte signature of the message, if SMB2_FLAGS_SIGNED
    /// is set in the Flags field of the SMB2 header and the message is not encrypted.
    /// If the message is not signed, this field MUST be 0.
    signature: Option<String>,
}

impl SyncHeader {
    /// Creates a new sync header by setting the protocol id and structure size initially.
    pub fn default() -> Self {
        SyncHeader {
            generic: GenericHeader::default(),
            reserved: None,
            tree_id: None,
            session_id: None,
            signature: None,
        }
    }
}

impl std::fmt::Display for SyncHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Sync Header: \n\t{}\n\t{}\n\t{}\n\t{}\n\t{}",
            self.generic,
            GenericHeader::print_optional_string(self.reserved.clone()),
            GenericHeader::print_optional_string(self.tree_id.clone()),
            GenericHeader::print_optional_string(self.session_id.clone()),
            GenericHeader::print_optional_string(self.signature.clone()),
        )
    }
}
