/// Query Info structure size of 41 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x29\x00";

/// The SMB2 QUERY_INFO Request packet is sent by a client to request
/// information on a file, named pipe, or underlying volume.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QueryInfo {
    /// StructureSize (2 bytes): The client MUST set this field to 41,
    /// indicating the size of the request structure, not including the header.
    /// The client MUST set this field to this value regardless of how long Buffer[]
    /// actually is in the request being sent.
    pub structure_size: Vec<u8>,
    /// InfoType (1 byte): The type of information queried.
    pub info_type: Vec<u8>,
    /// FileInfoClass (1 byte): For file information queries.
    /// TODO: implement enum for all file information classes.
    /// For now, its default value will be level 18,
    /// which requests all file information about the specified file from the server.
    /// Check MS-FSCC Section 2.4 and 2.5 for all information.
    pub file_info_class: Vec<u8>,
    /// OutputBufferLength (4 bytes): The maximum number of bytes of information
    /// the server can send in the response.
    pub output_buffer_length: Vec<u8>,
    /// InputBufferOffset (2 bytes): The offset, in bytes, from the beginning of the
    /// SMB2 header to the input buffer. For quota requests, the input buffer MUST contain
    /// an SMB2_QUERY_QUOTA_INFO. For FileFullEaInformation requests, the input buffer MUST
    /// contain the user supplied EA list with zero or more FILE_GET_EA_INFORMATION structures.
    /// For other information queries, this field SHOULD be set to 0.
    pub input_buffer_offset: Vec<u8>,
    /// Reserved (2 bytes): This field MUST NOT be used and MUST be reserved.
    /// The client MUST set this field to 0, and the server MUST ignore it on receipt.
    pub reserved: Vec<u8>,
    /// InputBufferLength (4 bytes): The length of the input buffer. For quota requests,
    /// this MUST be the length of the contained SMB2_QUERY_QUOTA_INFO embedded in the request.
    /// For FileFullEaInformation requests, this MUST be set to the length of the user supplied EA list.
    /// For other information queries, this field SHOULD be set to 0 and the server MUST ignore it on receipt.
    pub input_buffer_length: Vec<u8>,
    /// AdditionalInformation (4 bytes): Provides additional information to the server.
    /// TODO: Implement enum for all additional information types.
    /// For now, this field will be set to zero.
    pub additional_information: Vec<u8>,
    /// If FileFullEaInformation is being queried and the application has not provided a
    /// list of EAs to query, but has provided an index into the object's full extended attribute
    /// information array at which to start the query, this field MUST contain a ULONG representation
    /// of that index. For all other queries, this field MUST be set to 0 and the server MUST ignore it.
    pub file_full_ea_name_information: Vec<u8>,
    /// Flags (4 bytes): The flags MUST be set to a combination of zero or more of these bit values
    /// for a FileFullEaInformation query.
    /// For all other queries, the client MUST set this field to 0, and the server MUST ignore it on receipt.
    pub flags: Vec<u8>,
    /// FileId (16 bytes): An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    /// Queries for underlying object store or quota information are directed to the volume on which the file resides.
    pub file_id: Vec<u8>,
    /// Buffer (variable): A variable-length buffer containing the input buffer for the request,
    /// as described by the InputBufferOffset and InputBufferLength fields
    /// For quota requests, the input Buffer MUST contain an SMB2_QUERY_QUOTA_INFO.
    /// For a FileFullEaInformation query, the Buffer MUST be in one of the following formats:
    /// - A zero-length buffer as indicated by an InputBufferLength that is equal to zero.
    /// - A list of FILE_GET_EA_INFORMATION structures provided by the application.
    pub buffer: Vec<u8>,
}

impl QueryInfo {
    /// Creates a new instance of the query info.
    pub fn default() -> Self {
        QueryInfo {
            structure_size: STRUCTURE_SIZE.to_vec(),
            info_type: Vec::new(),
            file_info_class: vec![18],
            output_buffer_length: Vec::new(),
            input_buffer_offset: vec![0; 2],
            reserved: vec![0; 2],
            input_buffer_length: vec![0; 4],
            additional_information: vec![0; 4],
            file_full_ea_name_information: Vec::new(),
            flags: Vec::new(),
            file_id: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

/// InfoType (1 byte): The type of information queried.
/// This field MUST contain one of the following values:
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InfoType {
    File,
    FileSystem,
    InfoSecurity,
    InfoQuota,
}

impl InfoType {
    /// Unpacks the byte code of the corresponding info type.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            InfoType::File => b"\x01".to_vec(),
            InfoType::FileSystem => b"\x02".to_vec(),
            InfoType::InfoSecurity => b"\x03".to_vec(),
            InfoType::InfoQuota => b"\x04".to_vec(),
        }
    }
}

/// Flags (4 bytes): The flags MUST be set to a combination of zero or
/// more of these bit values for a FileFullEaInformation query.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InfoFlags {
    RestartScan,
    ReturnSingleEntry,
    IndexSpecified,
}

impl InfoFlags {
    /// Unpacks the the byte code of the corresponding info flag.
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            InfoFlags::RestartScan => 0x00000001,
            InfoFlags::ReturnSingleEntry => 0x0000002,
            InfoFlags::IndexSpecified => 0x00000004,
        }
    }

    /// Add the values of a list of chosen info flags and return the sum as a hex string.
    pub fn return_sum_of_chosen_capabilities(info_flags: Vec<InfoFlags>) -> Vec<u8> {
        let combined_flags: u32 = info_flags
            .iter()
            .fold(0u32, |acc, flag| acc + flag.unpack_byte_code());

        combined_flags.to_le_bytes().to_vec()
    }
}
