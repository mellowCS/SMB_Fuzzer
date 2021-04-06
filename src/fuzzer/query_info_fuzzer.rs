use crate::smb2::requests::query_info::{InfoType, QueryInfo};

pub const DEFAULT_BUFFER_LENGTH: &[u8; 4] = b"\xff\xff\x00\x00";

/// Fuzzess the query info request with predefined values.
pub fn fuzz_query_info_with_predefined_values(file_id: Vec<u8>) -> QueryInfo {
    let mut query_info_request = QueryInfo::default();

    query_info_request.info_type = rand::random::<InfoType>().unpack_byte_code();
    query_info_request.output_buffer_length = DEFAULT_BUFFER_LENGTH.to_vec();
    query_info_request.flags = vec![0; 4];
    query_info_request.file_id = file_id;
    query_info_request.buffer = vec![0];

    query_info_request
}
