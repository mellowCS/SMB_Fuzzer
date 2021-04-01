//! The SMB2 CREATE Response packet is sent by the server to notify
//! the client of the status of its SMB2 CREATE Request.

/// Represents the structure size of the create response.
const STRUCTURE_SIZE: &[u8; 2] = b"\x59\x00";

/// A struct that represents a create response.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Create {
    /// StructureSize (2 bytes): The server MUST set this field to 89, indicating
    /// the size of the request structure, not including the header.
    /// The server MUST set this field to this value regardless of how long Buffer[]
    /// actually is in the request being sent.
    pub structure_size: Vec<u8>,
    /// OplockLevel (1 byte): The oplock level that is granted to the client for this open.
    pub op_lock_level: Vec<u8>,
    /// Flags (1 byte): If the server implements the SMB 3.x dialect family, this field MUST be
    /// constructed. Otherwise, this field MUST NOT be used and MUST be reserved.
    pub flags: Vec<u8>,
    /// CreateAction (4 bytes): The action taken in establishing the open.
    /// This field MUST contain one of the following values.
    pub create_action: Vec<u8>,
    /// CreationTime (8 bytes): The time when the file was created.
    pub creation_time: Vec<u8>,
    /// LastAccessTime (8 bytes): The time the file was last accessed.
    pub last_access_time: Vec<u8>,
    /// LastWriteTime (8 bytes): The time when data was last written to the file.
    pub last_write_time: Vec<u8>,
    /// ChangeTime (8 bytes): The time when the file was last modified.
    pub change_time: Vec<u8>,
    /// AllocationSize (8 bytes): The size, in bytes, of the data that is allocated to the file.
    pub allocation_size: Vec<u8>,
    /// EndofFile (8 bytes): The size, in bytes, of the file.
    pub end_of_file: Vec<u8>,
    /// FileAttributes (4 bytes): The attributes of the file.
    pub file_attributes: Vec<u8>,
    /// Reserved (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// The server SHOULD set this to 0, and the client MUST ignore it on receipt.
    pub reserved: Vec<u8>,
    /// FileId (16 bytes): An SMB2_FILEID.
    pub file_id: Vec<u8>,
    /// CreateContextsOffset (4 bytes): The offset, in bytes, from the beginning of
    /// the SMB2 header to the first 8-byte aligned SMB2_CREATE_CONTEXT response that
    /// is contained in this response. If none are being returned in the response, this value MUST be 0.
    pub create_contexts_offset: Vec<u8>,
    /// CreateContextsLength (4 bytes): The length, in bytes, of the list of SMB2_CREATE_CONTEXT
    /// response structures that are contained in this response.
    pub create_contexts_length: Vec<u8>,
    /// Buffer (variable): A variable-length buffer that contains the list of create contexts
    /// that are contained in this response, as described by CreateContextsOffset and CreateContextsLength.
    /// This takes the form of a list of SMB2_CREATE_CONTEXT Response Values.
    pub buffer: Vec<u8>,
}

impl Create {
    /// Creates a new instance of the create response.
    pub fn default() -> Self {
        Create {
            structure_size: STRUCTURE_SIZE.to_vec(),
            op_lock_level: Vec::new(),
            flags: vec![0],
            create_action: Vec::new(),
            creation_time: Vec::new(),
            last_access_time: Vec::new(),
            last_write_time: Vec::new(),
            change_time: Vec::new(),
            allocation_size: Vec::new(),
            end_of_file: Vec::new(),
            file_attributes: Vec::new(),
            reserved: vec![0; 4],
            file_id: Vec::new(),
            create_contexts_offset: Vec::new(),
            create_contexts_length: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

/// CreateAction (4 bytes): The action taken in establishing the open.
/// This field MUST contain one of the following values.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CreateAction {
    Supersede,
    Opened,
    Created,
    Overwritten,
}

impl CreateAction {
    /// Unpacks the byte code of the corresponding create action.
    pub fn unpack_byte_code(self) -> Vec<u8> {
        match self {
            CreateAction::Supersede => b"\x00\x00\x00\x00".to_vec(),
            CreateAction::Opened => b"\x01\x00\x00\x00".to_vec(),
            CreateAction::Created => b"\x02\x00\x00\x00".to_vec(),
            CreateAction::Overwritten => b"\x03\x00\x00\x00".to_vec(),
        }
    }
}
