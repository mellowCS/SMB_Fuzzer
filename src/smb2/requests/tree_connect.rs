//! This module represents a tree connect request.
//! The SMB2 TREE_CONNECT Request packet is sent by a client to request access to a particular share on the server.
//! This request is composed of an SMB2 Packet Header that is followed by this request structure.

use crate::smb2::helper_functions::tree_connect_context::TreeConnectContext;

/// tree connect request size of 9 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x09\x00";

/// A struct that represents a tree connect request
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TreeConnect {
    /// StructureSize (2 bytes): The client MUST set this field to 9,
    /// indicating the size of the request structure, not including the header.
    /// The client MUST set it to this value regardless of how long Buffer[]
    /// actually is in the request being sent.
    pub structure_size: Vec<u8>,
    /// Flags/Reserved (2 bytes): This field is interpreted in different ways
    /// depending on the SMB2 dialect. In the SMB 3.1.1 dialect,
    /// this field is interpreted as the Flags field, which indicates how to process the operation.
    pub flags: Vec<u8>,
    /// PathOffset (2 bytes): The offset, in bytes, of the full share path name from the beginning
    /// of the packet header. The full share pathname is Unicode in the form "\\server\share"
    /// for the request. The server component of the path MUST be less than 256 characters in length,
    /// and it MUST be a NetBIOS name, a fully qualified domain name (FQDN), or a textual IPv4 or IPv6 address.
    /// The share component of the path MUST be less than or equal to 80 characters in length.
    /// The share name MUST NOT contain any invalid characters.
    pub path_offset: Vec<u8>,
    /// PathLength (2 bytes): The length, in bytes, of the full share path name.
    pub path_length: Vec<u8>,
    /// Buffer (variable): If SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT is not set in the Flags field of this structure,
    /// this field is a variable-length buffer that contains the full share path name.
    /// If SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT is set in the Flags field in this structure,
    /// this field is a variable-length buffer that contains the tree connect request extension
    pub buffer: Vec<u8>,
}

impl TreeConnect {
    /// Creates a new instance of the tree connect request.
    pub fn default() -> Self {
        TreeConnect {
            structure_size: STRUCTURE_SIZE.to_vec(),
            flags: Vec::new(),
            path_offset: Vec::new(),
            path_length: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

/// *Cluster Reconnect*:
///     - When set, indicates that the client has previously connected
///       to the specified cluster share using the SMB dialect of the
///       connection on which the request is received.
///
/// *Redirect To Owner*:
///     - When set, indicates that the client can handle synchronous share
///       redirects via a Share Redirect error context response.
///
/// *Extension Present*:
///     - When set, indicates that a tree connect request extension, is present,
///       starting at the Buffer field of this tree connect request.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Flags {
    ClusterReconnect,
    RedirectToOwner,
    ExtensionPresent,
}

impl Flags {
    /// Unpacks the byte code of tree connect request flags.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Flags::ClusterReconnect => b"\x01\x00".to_vec(),
            Flags::RedirectToOwner => b"\x02\x00".to_vec(),
            Flags::ExtensionPresent => b"\x04\x00".to_vec(),
        }
    }
}

/// If the Flags field of the SMB2 TREE_CONNECT request has the
/// SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT bit set,
/// the following structure MUST be added at the beginning of the Buffer field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TreeConnectExtension {
    /// TreeConnectContextOffset (4 bytes): The offset from the start
    /// of the SMB2 TREE_CONNECT request of an array of tree connect contexts.
    tree_connect_context_offset: Vec<u8>,
    /// TreeConnectContextCount (2 bytes): The count of elements in the tree
    /// connect context array.
    tree_connect_context_count: Vec<u8>,
    /// Reserved (10 bytes): MUST be set to zero.
    reserved: Vec<u8>,
    /// PathName (variable): This field is a variable-length buffer that contains
    /// the full share path name
    /// The full share pathname is Unicode in the form "\\server\share" for the request
    path_name: Vec<u8>,
    /// TreeConnectContexts (variable): A variable length array of
    /// SMB2_TREE_CONNECT_CONTEXT structures
    tree_connect_contexts: Vec<TreeConnectContext>,
}

impl TreeConnectExtension {
    /// Creates a new Tree Connect Extension instance.
    pub fn default() -> Self {
        TreeConnectExtension {
            tree_connect_context_offset: Vec::new(),
            tree_connect_context_count: Vec::new(),
            reserved: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            path_name: Vec::new(),
            tree_connect_contexts: Vec::new(),
        }
    }
}
