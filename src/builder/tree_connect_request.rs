use crate::smb2::{header, requests};

pub const DEFAULT_BUFFER: &[u8; 42] =
    b"\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\
\x38\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x37\x00\x31\x00\x5c\x00\
\x73\x00\x68\x00\x61\x00\x72\x00\x65\x00";

pub const DEFAULT_PATH_OFFSET: &[u8; 2] = b"\x48\x00";
pub const DEFAULT_PATH_LENGTH: &[u8; 2] = b"\x2a\x00";

/// Builds a working default tree connect request.
pub fn build_default_tree_connect_request(
    session_id: Vec<u8>,
) -> (header::SyncHeader, requests::tree_connect::TreeConnect) {
    (
        super::build_sync_header(
            header::Commands::TreeConnect,
            1,
            8064,
            None,
            Some(session_id),
            3,
        ),
        build_default_tree_connect_request_body(),
    )
}

/// Builds a working default tree connect request body.
pub fn build_default_tree_connect_request_body() -> requests::tree_connect::TreeConnect {
    let mut tree_connect = requests::tree_connect::TreeConnect::default();
    tree_connect.flags = vec![0; 2];
    tree_connect.path_offset = DEFAULT_PATH_OFFSET.to_vec();
    tree_connect.path_length = DEFAULT_PATH_LENGTH.to_vec();
    tree_connect.buffer = DEFAULT_BUFFER.to_vec();

    tree_connect
}
