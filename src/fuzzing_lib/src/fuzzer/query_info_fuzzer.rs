use super::create_random_byte_array_of_predefined_length;
use super::create_random_byte_array_with_random_length;
use crate::smb2::requests::query_info::{InfoType, QueryInfo};

pub const DEFAULT_BUFFER_LENGTH: &[u8; 4] = b"\xff\xff\x00\x00";

/// Fuzzes the query info request with predefined values.
pub fn fuzz_query_info_with_predefined_values(file_id: Vec<u8>) -> QueryInfo {
    let mut query_info_request = QueryInfo::default();

    query_info_request.info_type = rand::random::<InfoType>().unpack_byte_code();
    query_info_request.output_buffer_length = DEFAULT_BUFFER_LENGTH.to_vec();
    query_info_request.flags = vec![0; 4];
    query_info_request.file_id = file_id;
    query_info_request.buffer = vec![0];

    query_info_request
}

/// Fuzzes the query info request with random values that comply to the size restrictions of certain fields.
pub fn fuzz_query_info_with_random_fields() -> QueryInfo {
    let mut query_info_request = QueryInfo::default();

    query_info_request.structure_size = create_random_byte_array_of_predefined_length(2);
    query_info_request.info_type = create_random_byte_array_of_predefined_length(1);
    query_info_request.file_info_class = create_random_byte_array_of_predefined_length(1);
    query_info_request.output_buffer_length = create_random_byte_array_of_predefined_length(4);
    query_info_request.input_buffer_offset = create_random_byte_array_of_predefined_length(2);
    query_info_request.reserved = create_random_byte_array_of_predefined_length(2);
    query_info_request.input_buffer_length = create_random_byte_array_of_predefined_length(4);
    query_info_request.additional_information = create_random_byte_array_of_predefined_length(4);
    query_info_request.flags = create_random_byte_array_of_predefined_length(4);
    query_info_request.file_id = create_random_byte_array_of_predefined_length(16);
    query_info_request.buffer = create_random_byte_array_with_random_length();

    query_info_request
}

/// Fuzzes the query info request with random values of random length.
pub fn fuzz_query_info_completely_random() -> QueryInfo {
    let mut query_info_request = QueryInfo::default();

    query_info_request.structure_size = create_random_byte_array_with_random_length();
    query_info_request.info_type = create_random_byte_array_with_random_length();
    query_info_request.file_info_class = create_random_byte_array_with_random_length();
    query_info_request.output_buffer_length = create_random_byte_array_with_random_length();
    query_info_request.input_buffer_offset = create_random_byte_array_with_random_length();
    query_info_request.reserved = create_random_byte_array_with_random_length();
    query_info_request.input_buffer_length = create_random_byte_array_with_random_length();
    query_info_request.additional_information = create_random_byte_array_with_random_length();
    query_info_request.flags = create_random_byte_array_with_random_length();
    query_info_request.file_id = create_random_byte_array_with_random_length();
    query_info_request.buffer = create_random_byte_array_with_random_length();

    query_info_request
}
