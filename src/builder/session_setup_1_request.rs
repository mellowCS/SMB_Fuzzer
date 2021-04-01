use crate::smb2::{header, helper_functions::fields, requests};

pub const INITIAL_SECURITY_BLOB: &[u8;74] = b"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\
                                             \x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\
                                             \x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x05\x02\
                                             \x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x28\x00\
                                             \x00\x00\x06\x01\x00\x00\x00\x00\x00\x0f";

pub const DEFAULT_BUFFER_OFFSET: &[u8; 2] = b"\x58\x00";
pub const DEFAULT_BUFFER_LENGTH: &[u8; 2] = b"\x4a\x00";

/// Builds a working default session setup 1 request.
pub fn build_default_session_setup_1_request(
) -> (header::SyncHeader, requests::session_setup::SessionSetup) {
    (
        super::build_sync_header(header::Commands::SessionSetup, 1, 8192, None, None, 1),
        build_default_session_setup_1_request_body(),
    )
}

/// Builds a working default session setup 1 request body.
pub fn build_default_session_setup_1_request_body() -> requests::session_setup::SessionSetup {
    let mut session_req = requests::session_setup::SessionSetup::default();

    session_req.flags = vec![0];
    session_req.security_mode = fields::SecurityMode::NegotiateSigningEnabled.unpack_byte_code(1);
    session_req.capabilities = fields::Capabilities::return_sum_of_chosen_capabilities(vec![
        fields::Capabilities::GlobalCapDFS,
    ]);
    session_req.channel = vec![0; 4];
    session_req.security_buffer_offset = DEFAULT_BUFFER_OFFSET.to_vec();
    session_req.security_buffer_length = DEFAULT_BUFFER_LENGTH.to_vec();
    session_req.buffer = INITIAL_SECURITY_BLOB.to_vec();
    session_req.previous_session_id = vec![0; 8];

    session_req
}
