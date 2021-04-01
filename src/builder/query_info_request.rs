use crate::smb2::{
    header,
    requests::{self, query_info::InfoType},
};

pub const DEFAULT_BUFFER_LENGTH: &[u8; 4] = b"\xff\xff\x00\x00";

/// Builds a working default query info request.
pub fn build_default_query_info_request(
    tree_id: Vec<u8>,
    session_id: Vec<u8>,
    file_id: Vec<u8>,
) -> (header::SyncHeader, requests::query_info::QueryInfo) {
    (
        super::build_sync_header(
            header::Commands::QueryInfo,
            1,
            7936,
            Some(tree_id),
            Some(session_id),
            5,
        ),
        build_default_query_info_request_body(file_id),
    )
}

/// Builds a working default query info request body.
pub fn build_default_query_info_request_body(file_id: Vec<u8>) -> requests::query_info::QueryInfo {
    let mut query_info = requests::query_info::QueryInfo::default();

    query_info.info_type = InfoType::File.unpack_byte_code();
    query_info.output_buffer_length = DEFAULT_BUFFER_LENGTH.to_vec();
    query_info.flags = vec![0; 4];
    query_info.file_id = file_id;
    query_info.buffer = vec![0];

    query_info
}
