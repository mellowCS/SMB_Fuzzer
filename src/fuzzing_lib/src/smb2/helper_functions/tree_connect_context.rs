//! This module contains the tree connect contexts
//! The SMB2_TREE_CONNECT_CONTEXT structure is used by the
//! SMB2 TREE_CONNECT request and the SMB2 TREE_CONNECT response
//! to encode additional properties.

/// The SMB2_TREE_CONNECT_CONTEXT structure is used by the SMB2 TREE_CONNECT
/// request and the SMB2 TREE_CONNECT response to encode additional properties.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TreeConnectContext {
    /// ContextType (2 bytes): Specifies the type of context in the Data field.
    /// This field MUST be one of the types.
    context_type: Vec<u8>,
    /// DataLength (2 bytes): The length, in bytes, of the Data field.
    data_length: Vec<u8>,
    /// Reserved (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// This value MUST be set to 0 by the client, and MUST be ignored by the server.
    reserved: Vec<u8>,
    /// Data (variable): A variable-length field that contains the tree connect context
    /// specified by the ContextType field.
    data: Option<ContextType>,
}

impl TreeConnectContext {
    /// Creates a new instance of the Tree Connect Context.
    pub fn default() -> Self {
        TreeConnectContext {
            context_type: Vec::new(),
            data_length: Vec::new(),
            reserved: b"\x00\x00\x00\x00".to_vec(),
            data: None,
        }
    }
}

/// *Reserved Tree Connect Context ID*:
///     - This value is reserved. 0x0000
///
/// *Remoted Identity Tree Connect Context ID*:
///     - The Data field contains remoted identity tree connect context data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContextType {
    ReservedTreeConntectContextId,
    RemotedIdentityTreeConnectContextId(Box<RemotedIdentityTreeConnectContextId>),
}

/// The SMB2_REMOTED_IDENTITY_TREE_CONNECT context is specified in SMB2_TREE_CONNECT_CONTEXT
/// structure when the ContextType is set to SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RemotedIdentityTreeConnectContextId {
    /// TicketType (2 bytes): A 16-bit integer specifying the type of ticket requested.
    /// The value in this field MUST be set to 0x0001.
    ticket_type: Vec<u8>,
    /// TicketSize (2 bytes): A 16-bit integer specifying the total size of this structure.
    ticket_size: Vec<u8>,
    /// User (2 bytes): A 16-bit integer specifying the offset, in bytes, from the beginning
    /// of this structure to the user information in the TicketInfo buffer.
    /// The user information is stored in SID_ATTR_DATA format.
    user: Vec<u8>,
    /// UserName (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the null-terminated Unicode string containing
    /// the username in the TicketInfo field.
    user_name: Vec<u8>,
    /// Domain (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the null-terminated Unicode string containing
    /// the domain name in the TicketInfo field.
    domain: Vec<u8>,
    /// Groups (2 bytes): A 16-bit integer specifying the offset, in bytes, from the beginning
    /// of this structure to the information about the groups in the TicketInfo buffer.
    /// The information is stored in SID_ARRAY_DATA format.
    groups: Vec<u8>,
    /// RestrictedGroups (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the restricted groups
    /// in the TicketInfo field. The information is stored in SID_ARRAY_DATA format.
    restricted_groups: Vec<u8>,
    /// Privileges (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the privileges
    /// in the TicketInfo field. The information is stored in PRIVILEGE_ARRAY_DATA format.
    privileges: Vec<u8>,
    /// PrimaryGroup (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the primary group
    /// in the TicketInfo field. The information is stored in SID_ARRAY_DATA format.
    primary_group: Vec<u8>,
    /// Owner (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the owner
    /// in the TicketInfo field. The information is stored in BLOB_DATA format, where
    /// BlobData contains the SID, representing the owner, and BlobSize contains the size of SID.
    owner: Vec<u8>,
    /// DefaultDacl (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the DACL,
    /// in the TicketInfo field. Information about the DACL is stored in BLOB_DATA format,
    /// where BlobSize contains the size of the ACL structure, and BlobData contains the DACL data.
    default_dacl: Vec<u8>,
    /// DeviceGroups (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the device groups in the TicketInfo field.
    /// The information is stored in SID_ARRAY_DATA format.
    device_groups: Vec<u8>,
    /// UserClaims (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the user claims data in the TicketInfo field.
    /// Information about user claims is stored in BLOB_DATA format, where BlobData contains
    /// an array of CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structures, representing the claims
    /// issued to the user, and BlobSize contains the size of the user claims data.
    user_claims: Vec<u8>,
    /// DeviceClaims (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the device claims data in the TicketInfo field.
    /// Information about device claims is stored in BLOB_DATA format, where BlobData contains
    /// an array of CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structures, representing the claims
    /// issued to the account of the device which the user is connected from, and BlobSize
    /// contains the size of the device claims data.
    device_claims: Vec<u8>,
    /// TicketInfo (variable): A variable-length buffer containing the remoted identity
    /// tree connect context data, including the information about all the previously
    /// defined fields in this structure.
    ticket_info: Vec<u8>,
}

impl RemotedIdentityTreeConnectContextId {
    /// Creates a new instance of Remoted Identity TreeConnect Context Id.
    pub fn default() -> Self {
        RemotedIdentityTreeConnectContextId {
            ticket_type: b"\x00\x01".to_vec(),
            ticket_size: Vec::new(),
            user: Vec::new(),
            user_name: Vec::new(),
            domain: Vec::new(),
            groups: Vec::new(),
            restricted_groups: Vec::new(),
            privileges: Vec::new(),
            primary_group: Vec::new(),
            owner: Vec::new(),
            default_dacl: Vec::new(),
            device_groups: Vec::new(),
            user_claims: Vec::new(),
            device_claims: Vec::new(),
            ticket_info: Vec::new(),
        }
    }
}

/// Contains information about the use in the ticket info.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SidAttrData {
    /// SidData (variable): SID, information in BLOB_DATA format.
    /// BlobSize MUST be set to the size of SID and BlobData MUST be set to the SID value.
    sid_data: Vec<u8>,
    /// Attr (4 bytes): Specified attributes of the SID.
    attr: Vec<u8>,
}

impl SidAttrData {
    /// Creates a new instance of SID Attr Data.
    pub fn default() -> Self {
        SidAttrData {
            sid_data: Vec::new(),
            attr: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Attr {
    GroupEnabled,
    GroupEnabledByDefault,
    GroupIntegrity,
    GroupIntegrityEnabled,
    GroupLogonId,
    GroupMandatory,
    GroupOwner,
    GroupResource,
    GroupUseForDenyOnly,
}

impl Attr {
    /// Unpacks the byte code for SID Attr.
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            Attr::GroupEnabled => 0x00000004,
            Attr::GroupEnabledByDefault => 0x00000002,
            Attr::GroupIntegrity => 0x00000020,
            Attr::GroupIntegrityEnabled => 0x00000040,
            Attr::GroupLogonId => 0xC0000000,
            Attr::GroupMandatory => 0x00000001,
            Attr::GroupOwner => 0x00000008,
            Attr::GroupResource => 0x20000000,
            Attr::GroupUseForDenyOnly => 0x00000010,
        }
    }
}

/// Represents information about owner, user and device claims, and default dacl
/// in the ticket fields.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlobData {
    /// BlobSize (2 bytes): Size of the data, in bytes, in BlobData.
    blob_size: Vec<u8>,
    /// BlobData (variable): Blob data.
    blob_data: Vec<u8>,
}

impl BlobData {
    /// Creates a new instance of Blobdata.
    pub fn default() -> Self {
        BlobData {
            blob_size: Vec::new(),
            blob_data: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SidArrayData {
    /// SidAttrCount (2 bytes): Number of SID_ATTR_DATA elements in SidAttrList array.
    sid_attr_count: Vec<u8>,
    /// SidAttrList (variable): An array with SidAttrCount number of SID_ATTR_DATA elements.
    sid_attr_list: Vec<SidAttrData>,
}

impl SidArrayData {
    /// Creates a new instance of SID Array Data.
    pub fn default() -> Self {
        SidArrayData {
            sid_attr_count: Vec::new(),
            sid_attr_list: Vec::new(),
        }
    }
}

/// Contains information about privileges with a unique id.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LuidAttrData {
    /// Luid (8 bytes): Locally unique identifier
    luid: Vec<u8>,
    /// Attr (4 bytes): LUID attributes.
    /// The last two bits of the 32 bits contain the following values:
    ///     - Second to last => D:The privilege is enabled by default.
    ///     - Last => E:The privilege is enabled.
    ///     - All other bits SHOULD be 0 and ignored upon receipt.
    attr: Vec<u8>,
}

impl LuidAttrData {
    /// Creates a new instance of LUID Attr Data.
    pub fn default() -> Self {
        LuidAttrData {
            luid: Vec::new(),
            attr: Vec::new(),
        }
    }
}

/// Contains privilege information about multiple users.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrivilegeArrayData {
    /// PrivilegeCount (2 bytes): Number of PRIVILEGE_DATA elements in PrivilegeList array.
    privilege_count: Vec<u8>,
    /// PrivilegeList (variable): An array with PrivilegeCount number of PRIVILEGE_DATA elements.
    /// PRIVILEGE_DATA takes the form BLOB_DATA. BlobSize MUST be set to the size of LUID_ATTR_DATA
    /// structure and BlobData MUST be set to the LUID_ATTR_DATA.
    privilege_list: Vec<BlobData>,
}

impl PrivilegeArrayData {
    /// Creates a new instance of Privilege Array Data.
    pub fn default() -> Self {
        PrivilegeArrayData {
            privilege_count: Vec::new(),
            privilege_list: Vec::new(),
        }
    }
}
