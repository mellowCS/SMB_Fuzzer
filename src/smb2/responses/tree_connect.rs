//! The SMB2 TREE_CONNECT Response packet is sent by the server when an SMB2 TREE_CONNECT request is processed successfully by the server.
//! This response is composed of an SMB2 Packet Header that is followed by this response structure.

const STRUCTURE_SIZE: &[u8; 2] = b"\x10\x00";

/// A struct that represents a tree connect response.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TreeConnect {
    /// StructureSize (2 bytes): The server MUST set this field to 16,
    /// indicating the size of the response structure, not including the header.
    pub structure_size: Vec<u8>,
    /// ShareType (1 byte): The type of share being accessed.
    pub share_type: Option<ShareType>,
    /// Reserved (1 byte): This field MUST NOT be used and MUST be reserved.
    /// The server MUST set this to 0, and the client MUST ignore it on receipt.
    pub reserved: Vec<u8>,
    /// ShareFlags (4 bytes): This field contains properties for this share.
    ///
    /// This field MUST contain one of the following offline caching properties:
    /// SMB2_SHAREFLAG_MANUAL_CACHING, SMB2_SHAREFLAG_AUTO_CACHING,
    /// SMB2_SHAREFLAG_VDO_CACHING and SMB2_SHAREFLAG_NO_CACHING.
    ///
    /// This field MUST contain zero or more of the following values:
    /// SMB2_SHAREFLAG_DFS, SMB2_SHAREFLAG_DFS_ROOT,
    /// SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS, SMB2_SHAREFLAG_FORCE_SHARED_DELETE,
    /// SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING, SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM,
    /// SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK and SMB2_SHAREFLAG_ENABLE_HASH.
    pub share_flags: Vec<u8>,
    /// Capabilities (4 bytes): Indicates various capabilities for this share.
    pub capabilities: Vec<u8>,
    /// MaximalAccess (4 bytes): Contains the maximal access for the user that
    /// establishes the tree connect on the share based on the share's permissions.
    pub maximal_access: Vec<u8>,
}

impl TreeConnect {
    /// Creates a new instance of tree connect.
    pub fn default() -> Self {
        TreeConnect {
            structure_size: STRUCTURE_SIZE.to_vec(),
            share_type: None,
            reserved: b"\x00".to_vec(),
            share_flags: Vec::new(),
            capabilities: Vec::new(),
            maximal_access: Vec::new(),
        }
    }
}

/// *Disk*:
///     - Physical disk share.
///
/// *Pipe*:
///     - Named pipe share.
///
/// *Print*:
///     - Printer share.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ShareType {
    Disk,
    Pipe,
    Print,
}

impl ShareType {
    /// Unpacks the byte code of the share type.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            ShareType::Disk => b"\x01".to_vec(),
            ShareType::Pipe => b"\x02".to_vec(),
            ShareType::Print => b"\x03".to_vec(),
        }
    }

    /// Maps the incoming byte code to the corresponding share type.
    pub fn map_byte_code_to_share_type(byte_code: Vec<u8>) -> Self {
        if let Some(code) = byte_code.get(0) {
            match code {
                1 => ShareType::Disk,
                2 => ShareType::Pipe,
                3 => ShareType::Print,
                _ => panic!("Invalid share type from tree connect_response."),
            }
        } else {
            panic!("Empty share type from tree connect response.")
        }
    }
}

/// *Manual Caching*:
///     - The client can cache files that are explicitly selected by the user for offline use.
///
/// *Auto Caching*:
///     - The client can automatically cache files that are used by the user for offline access.
///
/// *VDO Caching*:
///     - The client can automatically cache files that are used by the user for offline access
///       and can use those files in an offline mode even if the share is available.
///
/// *No Caching*:
///     - Offline caching MUST NOT occur.
///
/// *DFS*:
///     - The specified share is present in a Distributed File System (DFS) tree structure.
///       The server SHOULD set the SMB2_SHAREFLAG_DFS bit in the ShareFlags field if the
///       per-share property Share.IsDfs is TRUE.
///
/// *DFS Root*:
///     - The specified share is present in a DFS tree structure.
///       The server SHOULD set the SMB2_SHAREFLAG_DFS_ROOT bit in the ShareFlags field
///       if the per-share property Share.IsDfs is TRUE.
///
/// *Restrict Exclusive Opens*:
///     - The specified share disallows exclusive file opens that deny reads to an open file.
///
/// *Force Shared Delete*:
///     - The specified share disallows clients from opening files on the share in an exclusive
///       mode that prevents the file from being deleted until the client closes the file.
///
/// *Allow Namespace Caching*:
///     - The client MUST ignore this flag
///
/// *Access Based Directory Enum*:
///     - The server will filter directory entries based on the access permissions of the client.
///
/// *Force Level II Oplock*:
///     - The server will not issue exclusive caching rights on this share.
///
/// *Enable Hash V1*:
///     - The share supports hash generation for branch cache retrieval of data.
///       This flag is not valid for the SMB 2.0.2 dialect.
///
/// *Enable Hash V2*:
///     - The share supports v2 hash generation for branch cache retrieval of data.
///       This flag is not valid for the SMB 2.0.2 and SMB 2.1 dialects.
///
/// *Encrypt Data*:
///     - The server requires encryption of remote file access messages on this share,
///       per the conditions. This flag is only valid for the SMB 3.x dialect family.
///
/// *Identity Remoting*:
///     - The share supports identity remoting. The client can request remoted identity
///       access for the share via the SMB2_REMOTED_IDENTITY_TREE_CONNECT context.
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ShareFlags {
    ManualCaching,
    AutoCaching,
    VDOCaching,
    NoCaching,
    DFS,
    DFSRoot,
    RestrictExclusiveOpens,
    ForceSharedDelete,
    AllowNamespaceCaching,
    AccessBasedDirectoryEnum,
    ForceLevelIIOplock,
    EnableHashV1,
    EnableHashV2,
    EncryptData,
    IdentityRemoting,
}

impl ShareFlags {
    /// Unpacks the byte code of share flags.
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            ShareFlags::ManualCaching => 0x00000000,
            ShareFlags::AutoCaching => 0x00000010,
            ShareFlags::VDOCaching => 0x00000020,
            ShareFlags::NoCaching => 0x00000030,
            ShareFlags::DFS => 0x00000001,
            ShareFlags::DFSRoot => 0x00000002,
            ShareFlags::RestrictExclusiveOpens => 0x00000100,
            ShareFlags::ForceSharedDelete => 0x00000200,
            ShareFlags::AllowNamespaceCaching => 0x00000400,
            ShareFlags::AccessBasedDirectoryEnum => 0x00000800,
            ShareFlags::ForceLevelIIOplock => 0x00001000,
            ShareFlags::EnableHashV1 => 0x00002000,
            ShareFlags::EnableHashV2 => 0x00004000,
            ShareFlags::EncryptData => 0x00008000,
            ShareFlags::IdentityRemoting => 0x00040000,
        }
    }
}

/// *DFS*:
///     - The specified share is present in a DFS tree structure.
///       The server MUST set the SMB2_SHARE_CAP_DFS bit in the Capabilities
///       field if the per-share property Share.IsDfs is TRUE.
///
/// *Continuous Availability*:
///     - The specified share is continuously available.
///       This flag is only valid for the SMB 3.x dialect family.
///
/// *Scaleout*:
///     - The specified share is present on a server configuration which
///       facilitates faster recovery of durable handles. This flag is only valid
///       for the SMB 3.x dialect family.
///
/// *Cluster*:
///     - The specified share is present on a server configuration which provides
///       monitoring of the availability of share through the Witness service.
///       This flag is only valid for the SMB 3.x dialect family.
///
/// *Asymmetric*:
///     - The specified share is present on a server configuration that allows
///       dynamic changes in the ownership of the share. This flag is not valid
///       for the SMB 2.0.2, 2.1, and 3.0 dialects.
///
/// *Redirect To Owner*:
///     - The specified share is present on a server configuration that supports
///       synchronous share level redirection via a Share Redirect error context response.
///       This flag is not valid for SMB 2.0.2, 2.1, 3.0, and 3.0.2 dialects.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Capabilities {
    DFS,
    ContinuousAvailability,
    Scaleout,
    Cluster,
    Asymmetric,
    RedirectToOwner,
}

impl Capabilities {
    /// Unpacks the byte code for tree connect capabilities.
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            Capabilities::DFS => 0x00000008,
            Capabilities::ContinuousAvailability => 0x00000010,
            Capabilities::Scaleout => 0x00000020,
            Capabilities::Cluster => 0x00000040,
            Capabilities::Asymmetric => 0x00000080,
            Capabilities::RedirectToOwner => 0x00000100,
        }
    }
}
