pub mod create_options;
pub mod file_access_mask;

pub const STRUCTURE_SIZE: &[u8; 2] = b"\x39\x00";

/// The SMB2 CREATE Request packet is sent by a client to request either
/// creation of or access to a file. In case of a named pipe or printer,
/// the server MUST create a new file.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Create {
    /// StructureSize (2 bytes): The client MUST set this field to 57,
    /// indicating the size of the request structure, not including the header.
    /// The client MUST set it to this value regardless of how long Buffer[]
    /// actually is in the request being sent.
    pub structure_size: Vec<u8>,
    /// SecurityFlags (1 byte): This field MUST NOT be used and MUST be reserved.
    /// The client MUST set this to 0, and the server MUST ignore it.
    pub security_flag: Vec<u8>,
    /// RequestedOplockLevel (1 byte): The requested oplock level. This field MUST
    /// contain one of the following values.<30> For named pipes, the server MUST
    /// always revert to SMB2_OPLOCK_LEVEL_NONE irrespective of the value of this field.
    pub requested_oplock_level: Vec<u8>,
    /// ImpersonationLevel (4 bytes): This field specifies the impersonation level requested
    /// by the application that is issuing the create request, and MUST contain one of the following values.
    pub impersonation_level: Vec<u8>,
    /// SmbCreateFlags (8 bytes): This field MUST NOT be used and MUST be reserved. The client SHOULD
    /// set this field to zero, and the server MUST ignore it on receipt.
    pub smb_create_flags: Vec<u8>,
    /// Reserved (8 bytes): This field MUST NOT be used and MUST be reserved. The client sets
    /// this to any value, and the server MUST ignore it on receipt.
    pub reserved: Vec<u8>,
    /// DesiredAccess (4 bytes): The level of access that is required
    pub desired_access: Vec<u8>,
    /// FileAttributes (4 bytes): This field MUST be a combination file attribute values
    ///  and MUST NOT include any values other than those specified in that section.
    pub file_attributes: Vec<u8>,
    /// ShareAccess (4 bytes): Specifies the sharing mode for the open. If ShareAccess values
    /// of FILE_SHARE_READ, FILE_SHARE_WRITE and FILE_SHARE_DELETE are set for a printer file or
    /// a named pipe, the server SHOULD ignore these values. The field MUST be constructed using
    /// a combination of zero or more of the following bit values.
    pub share_access: Vec<u8>,
    /// CreateDisposition (4 bytes): Defines the action the server MUST take if the file
    /// that is specified in the name field already exists. For opening named pipes, this
    /// field can be set to any value by the client and MUST be ignored by the server.
    /// For other files, this field MUST contain one of the following values.
    pub create_disposition: Vec<u8>,
    /// CreateOptions (4 bytes): Specifies the options to be applied when creating or
    /// opening the file. Combinations of the bit positions listed below are valid,
    /// unless otherwise noted. This field MUST be constructed using the following values.
    pub create_options: Vec<u8>,
    /// NameOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header
    /// to the 8-byte aligned file name. If SMB2_FLAGS_DFS_OPERATIONS is set in the Flags
    /// field of the SMB2 header, the file name includes a prefix that will be processed
    /// during DFS name normalization. Otherwise, the file name is relative to the share
    /// that is identified by the TreeId in the SMB2 header. The NameOffset field SHOULD
    /// be set to the offset of the Buffer field from the beginning of the SMB2 header.
    /// The file name (after DFS normalization if needed) MUST conform to the specification
    /// of a relative pathname.A zero length file name indicates a request to open the root of the share.
    pub name_offset: Vec<u8>,
    /// NameLength (2 bytes): The length of the file name, in bytes. If no file name is provided,
    ///this field MUST be set to 0.
    pub name_length: Vec<u8>,
    /// CreateContextsOffset (4 bytes): The offset, in bytes, from the beginning of the SMB2 header
    /// to the first 8-byte aligned SMB2_CREATE_CONTEXT structure in the request.
    /// If no SMB2_CREATE_CONTEXTs are being sent, this value MUST be 0.
    pub create_contexts_offset: Vec<u8>,
    /// CreateContextsLength (4 bytes): The length, in bytes, of the list of
    /// SMB2_CREATE_CONTEXT structures sent in this request.
    pub create_contexts_length: Vec<u8>,
    /// Buffer (variable): A variable-length buffer that contains the Unicode file name and
    /// create context list, as defined by NameOffset, NameLength, CreateContextsOffset,
    /// and CreateContextsLength. In the request, the Buffer field MUST be at least one byte in length.
    /// The file name (after DFS normalization if needed) MUST conform to the specification of a
    /// relative pathname.
    pub buffer: Vec<u8>,
}

impl Create {
    pub fn default() -> Self {
        Create {
            structure_size: STRUCTURE_SIZE.to_vec(),
            security_flag: vec![0],
            requested_oplock_level: Vec::new(),
            impersonation_level: Vec::new(),
            smb_create_flags: vec![0; 8],
            reserved: vec![0; 8],
            desired_access: Vec::new(),
            file_attributes: Vec::new(),
            share_access: Vec::new(),
            create_disposition: Vec::new(),
            create_options: Vec::new(),
            name_offset: Vec::new(),
            name_length: Vec::new(),
            create_contexts_offset: Vec::new(),
            create_contexts_length: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

/// OplockLevel (1 byte): The oplock level.
/// This field MUST contain one of the following values.
/// For named pipes, the server MUST always revert to SMB2_OPLOCK_LEVEL_NONE
/// irrespective of the value of this field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OplockLevel {
    None,
    Level2,
    Exclusive,
    Batch,
    Lease,
}

impl OplockLevel {
    /// Unpacks the byte code of the corresponding requested oplock level.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            OplockLevel::None => b"\x00".to_vec(),
            OplockLevel::Level2 => b"\x01".to_vec(),
            OplockLevel::Exclusive => b"\x08".to_vec(),
            OplockLevel::Batch => b"\x09".to_vec(),
            OplockLevel::Lease => b"\xff".to_vec(),
        }
    }
}

/// ImpersonationLevel (4 bytes): This field specifies the impersonation level
/// requested by the application that is issuing the create request, and MUST
/// contain one of the following values.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ImpersonationLevel {
    Anonymous,
    Identification,
    Impersonation,
    Delegate,
}

impl ImpersonationLevel {
    /// Unpacks the byte code of the corresponding impersonation level.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            ImpersonationLevel::Anonymous => b"\x00\x00\x00\x00".to_vec(),
            ImpersonationLevel::Identification => b"\x01\x00\x00\x00".to_vec(),
            ImpersonationLevel::Impersonation => b"\x02\x00\x00\x00".to_vec(),
            ImpersonationLevel::Delegate => b"\x03\x00\x00\x00".to_vec(),
        }
    }
}

/// ShareAccess (4 bytes): Specifies the sharing mode for the open.
/// If ShareAccess values of FILE_SHARE_READ, FILE_SHARE_WRITE and FILE_SHARE_DELETE
/// are set for a printer file or a named pipe, the server SHOULD ignore these values.
/// The field MUST be constructed using a combination of zero or more of the following bit values.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ShareAccess {
    ShareRead,
    ShareWrite,
    ShareDelete,
}

impl ShareAccess {
    /// Unpacks the byte code of the corresponding share access.
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            ShareAccess::ShareRead => 0x00000001,
            ShareAccess::ShareWrite => 0x00000002,
            ShareAccess::ShareDelete => 0x00000004,
        }
    }

    /// Returns a sum of the given share access type as a 4 byte array.
    pub fn return_sum_of_chosen_share_access(share_access: Vec<ShareAccess>) -> Vec<u8> {
        let combined_share_access: u32 = share_access
            .iter()
            .fold(0u32, |acc, access| acc + access.unpack_byte_code());

        combined_share_access.to_le_bytes().to_vec()
    }
}

/// CreateDisposition (4 bytes): Defines the action the server
/// MUST take if the file that is specified in the name field already exists.
/// For opening named pipes, this field can be set to any value by the client
/// and MUST be ignored by the server. For other files, this field MUST contain
/// one of the following values.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CreateDisposition {
    Supersede,
    Open,
    Create,
    OpenIf,
    Overwrite,
    OverwriteIf,
}

impl CreateDisposition {
    /// Unpacks the byte code of the corresponding create disposition.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            CreateDisposition::Supersede => b"\x00\x00\x00\x00".to_vec(),
            CreateDisposition::Open => b"\x01\x00\x00\x00".to_vec(),
            CreateDisposition::Create => b"\x02\x00\x00\x00".to_vec(),
            CreateDisposition::OpenIf => b"\x03\x00\x00\x00".to_vec(),
            CreateDisposition::Overwrite => b"\x04\x00\x00\x00".to_vec(),
            CreateDisposition::OverwriteIf => b"\x05\x00\x00\x00".to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sum_share_access() {
        assert_eq!(
            vec![7, 0, 0, 0],
            ShareAccess::return_sum_of_chosen_share_access(vec![
                ShareAccess::ShareRead,
                ShareAccess::ShareWrite,
                ShareAccess::ShareDelete
            ])
        );
        assert_eq!(
            vec![3, 0, 0, 0],
            ShareAccess::return_sum_of_chosen_share_access(vec![
                ShareAccess::ShareRead,
                ShareAccess::ShareWrite,
            ])
        );
        assert_eq!(
            vec![6, 0, 0, 0],
            ShareAccess::return_sum_of_chosen_share_access(vec![
                ShareAccess::ShareWrite,
                ShareAccess::ShareDelete
            ])
        );
        assert_eq!(
            vec![5, 0, 0, 0],
            ShareAccess::return_sum_of_chosen_share_access(vec![
                ShareAccess::ShareRead,
                ShareAccess::ShareDelete,
            ])
        );
    }
}
