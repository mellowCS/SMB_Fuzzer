use crate::smb2::{header, requests};

pub mod create_request;
pub mod negotiate_request;
pub mod query_info_request;
pub mod session_setup_1_request;
pub mod session_setup_2_request;
pub mod tree_connect_request;

/// Builds a sync header with the corresponding parameters.
/// - The tree id will only be set after the tree connect response from the server.
/// - The session id will only be set after the session setup response from the server.
pub fn build_sync_header(
    command: header::Commands,
    credit_charge: u16,
    credit_request: u16,
    tree_id: Option<Vec<u8>>,
    session_id: Option<Vec<u8>>,
    message_id: u64,
) -> header::SyncHeader {
    let mut header = header::SyncHeader::default();

    header.generic.credit_charge = credit_charge.to_le_bytes().to_vec();
    header.generic.channel_sequence = vec![0; 2];
    header.generic.reserved = vec![0; 2];
    header.generic.command = command.unpack_byte_code();
    header.generic.credit = credit_request.to_le_bytes().to_vec();
    header.generic.flags = header::Flags::DfsOperations.unpack_byte_code();
    header.generic.next_command = vec![0; 4];
    header.generic.message_id = message_id.to_le_bytes().to_vec();
    header.tree_id = match tree_id {
        Some(id) => id,
        None => vec![0; 4],
    };
    header.session_id = match session_id {
        Some(id) => id,
        None => vec![0; 8],
    };
    header.signature = vec![0; 16];

    header
}

/// Creates a complete create request.
pub fn build_default_echo_request() -> (header::SyncHeader, requests::echo::Echo) {
    (
        build_sync_header(header::Commands::Echo, 1, 7968, None, None, 6),
        requests::echo::Echo::default(),
    )
}

/// Creates a complete close request.
pub fn build_close_request(
    tree_id: Vec<u8>,
    session_id: Vec<u8>,
    file_id: Vec<u8>,
) -> (header::SyncHeader, requests::close::Close) {
    let mut close = requests::close::Close::default();
    close.file_id = file_id;
    (
        build_sync_header(
            header::Commands::Close,
            1,
            7872,
            Some(tree_id),
            Some(session_id),
            7,
        ),
        close,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sync_header() {
        let result = build_sync_header(
            header::Commands::SessionSetup,
            1,
            1,
            Some(vec![1, 0, 0, 0]),
            Some(vec![1, 0, 0, 0, 0, 0, 0, 0]),
            10,
        );

        assert_eq!(vec![1, 0], result.generic.credit_charge);
        assert_eq!(vec![1, 0], result.generic.credit);
        assert_eq!(vec![1, 0], result.generic.command);
        assert_eq!(vec![1, 0, 0, 0], result.tree_id);
        assert_eq!(vec![1, 0, 0, 0, 0, 0, 0, 0], result.session_id);
        assert_eq!(vec![10, 0, 0, 0, 0, 0, 0, 0], result.generic.message_id);
    }
}
