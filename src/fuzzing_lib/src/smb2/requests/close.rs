/// Read request size of 49 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x18\x00";

/// The SMB2 CLOSE Request packet is used by the client to close an instance
/// of a file that was opened previously with a successful SMB2 CREATE Request.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Close {
    /// StructureSize (2 bytes): The client MUST set this field to 24,
    /// indicating the size of the request structure, not including the header.
    pub structure_size: Vec<u8>,
    /// Flags (2 bytes): A Flags field indicates how to process the operation.
    pub flags: Vec<u8>,
    /// Reserved (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// The client MUST set this to 0, and the server MUST ignore it on receipt.
    pub reserved: Vec<u8>,
    /// FileId (16 bytes): An SMB2_FILEID structure.
    pub file_id: Vec<u8>,
}

impl Close {
    /// Creates a new instance of the close request.
    pub fn default() -> Self {
        Close {
            structure_size: STRUCTURE_SIZE.to_vec(),
            flags: vec![0; 2],
            reserved: vec![0; 4],
            file_id: Vec::new(),
        }
    }
}
