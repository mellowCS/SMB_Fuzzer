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
    context_type: Option<String>,
    /// DataLength (2 bytes): The length, in bytes, of the Data field.
    data_length: Option<String>,
    /// Reserved (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// This value MUST be set to 0 by the client, and MUST be ignored by the server.
    reserved: String,
    /// Data (variable): A variable-length field that contains the tree connect context
    /// specified by the ContextType field.
    data: Option<ContextType>,
}

impl TreeConnectContext {
    /// Creates a new instance of the Tree Connect Context.
    pub fn default() -> Self {
        TreeConnectContext {
            context_type: None,
            data_length: None,
            reserved: String::from("00000000"),
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
    ticket_type: String,
    /// TicketSize (2 bytes): A 16-bit integer specifying the total size of this structure.
    ticket_size: Option<String>,
    /// User (2 bytes): A 16-bit integer specifying the offset, in bytes, from the beginning
    /// of this structure to the user information in the TicketInfo buffer.
    /// The user information is stored in SID_ATTR_DATA format.
    user: Option<String>,
    /// UserName (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the null-terminated Unicode string containing
    /// the username in the TicketInfo field.
    user_name: Option<String>,
    /// Domain (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the null-terminated Unicode string containing
    /// the domain name in the TicketInfo field.
    domain: Option<String>,
    /// Groups (2 bytes): A 16-bit integer specifying the offset, in bytes, from the beginning
    /// of this structure to the information about the groups in the TicketInfo buffer.
    /// The information is stored in SID_ARRAY_DATA format.
    groups: Option<String>,
    /// RestrictedGroups (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the restricted groups
    /// in the TicketInfo field. The information is stored in SID_ARRAY_DATA format.
    restricted_groups: Option<String>,
    /// Privileges (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the privileges
    /// in the TicketInfo field. The information is stored in PRIVILEGE_ARRAY_DATA format.
    privileges: Option<String>,
    /// PrimaryGroup (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the primary group
    /// in the TicketInfo field. The information is stored in SID_ARRAY_DATA format.
    primary_group: Option<String>,
    /// Owner (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the owner
    /// in the TicketInfo field. The information is stored in BLOB_DATA format, where
    /// BlobData contains the SID, representing the owner, and BlobSize contains the size of SID.
    owner: Option<String>,
    /// DefaultDacl (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the DACL,
    /// in the TicketInfo field. Information about the DACL is stored in BLOB_DATA format,
    /// where BlobSize contains the size of the ACL structure, and BlobData contains the DACL data.
    default_dacl: Option<String>,
    /// DeviceGroups (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the information about the device groups in the TicketInfo field.
    /// The information is stored in SID_ARRAY_DATA format.
    device_groups: Option<String>,
    /// UserClaims (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the user claims data in the TicketInfo field.
    /// Information about user claims is stored in BLOB_DATA format, where BlobData contains
    /// an array of CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structures, representing the claims
    /// issued to the user, and BlobSize contains the size of the user claims data.
    user_claims: Option<String>,
    /// DeviceClaims (2 bytes): A 16-bit integer specifying the offset, in bytes,
    /// from the beginning of this structure to the device claims data in the TicketInfo field.
    /// Information about device claims is stored in BLOB_DATA format, where BlobData contains
    /// an array of CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structures, representing the claims
    /// issued to the account of the device which the user is connected from, and BlobSize
    /// contains the size of the device claims data.
    device_claims: Option<String>,
    /// TicketInfo (variable): A variable-length buffer containing the remoted identity
    /// tree connect context data, including the information about all the previously
    /// defined fields in this structure.
    ticket_info: Option<String>,
}

impl RemotedIdentityTreeConnectContextId {
    /// Creates a new instance of Remoted Identity TreeConnect Context Id.
    pub fn default() -> Self {
        RemotedIdentityTreeConnectContextId {
            ticket_type: String::from("0001"),
            ticket_size: None,
            user: None,
            user_name: None,
            domain: None,
            groups: None,
            restricted_groups: None,
            privileges: None,
            primary_group: None,
            owner: None,
            default_dacl: None,
            device_groups: None,
            user_claims: None,
            device_claims: None,
            ticket_info: None,
        }
    }
}

/// Contains information about the use in the ticket info.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SIDAttrData {
    /// SidData (variable): SID, information in BLOB_DATA format.
    /// BlobSize MUST be set to the size of SID and BlobData MUST be set to the SID value.
    sid_data: Option<String>,
    /// Attr (4 bytes): Specified attributes of the SID.
    attr: Option<String>,
}

impl SIDAttrData {
    /// Creates a new instance of SID Attr Data.
    pub fn default() -> Self {
        SIDAttrData {
            sid_data: None,
            attr: None,
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
    blob_size: Option<String>,
    /// BlobData (variable): Blob data.
    blob_data: Option<String>,
}

impl BlobData {
    /// Creates a new instance of Blobdata.
    pub fn default() -> Self {
        BlobData {
            blob_size: None,
            blob_data: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SIDArrayData {
    /// SidAttrCount (2 bytes): Number of SID_ATTR_DATA elements in SidAttrList array.
    sid_attr_count: Option<String>,
    /// SidAttrList (variable): An array with SidAttrCount number of SID_ATTR_DATA elements.
    sid_attr_list: Vec<SIDAttrData>,
}

impl SIDArrayData {
    /// Creates a new instance of SID Array Data.
    pub fn default() -> Self {
        SIDArrayData {
            sid_attr_count: None,
            sid_attr_list: Vec::new(),
        }
    }
}

/// Contains information about privileges with a unique id.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LUIDAttrData {
    /// Luid (8 bytes): Locally unique identifier
    luid: Option<String>,
    /// Attr (4 bytes): LUID attributes.
    /// The last two bits of the 32 bits contain the following values:
    ///     - Second to last => D:The privilege is enabled by default.
    ///     - Last => E:The privilege is enabled.
    ///     - All other bits SHOULD be 0 and ignored upon receipt.
    attr: Option<String>,
}

impl LUIDAttrData {
    /// Creates a new instance of LUID Attr Data.
    pub fn default() -> Self {
        LUIDAttrData {
            luid: None,
            attr: None,
        }
    }
}

/// Contains privilege information about multiple users.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrivilegeArrayData {
    /// PrivilegeCount (2 bytes): Number of PRIVILEGE_DATA elements in PrivilegeList array.
    privilege_count: Option<String>,
    /// PrivilegeList (variable): An array with PrivilegeCount number of PRIVILEGE_DATA elements.
    /// PRIVILEGE_DATA takes the form BLOB_DATA. BlobSize MUST be set to the size of LUID_ATTR_DATA
    /// structure and BlobData MUST be set to the LUID_ATTR_DATA.
    privilege_list: Vec<BlobData>,
}

impl PrivilegeArrayData {
    /// Creates a new instance of Privilege Array Data.
    pub fn default() -> Self {
        PrivilegeArrayData {
            privilege_count: None,
            privilege_list: Vec::new(),
        }
    }
}
