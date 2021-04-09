pub mod security_buffer;

use crate::{
    format::encoder::security_blob_encoder::encode_security_authentication,
    ntlmssp,
    smb2::{header, helper_functions::fields, requests},
};

const SECURITY_BUFFER_OFFSET: &[u8; 2] = b"\x58\x00";
const SECURITY_BUFFER_LENGTH: &[u8; 2] = b"\x56\x01";

/// Builds a working default session setup 2 request.
pub fn build_default_session_setup_authenticate_request(
    session_id: Vec<u8>,
    server_challenge_struct: ntlmssp::challenge::Challenge,
) -> (
    Option<header::SyncHeader>,
    Option<requests::session_setup::SessionSetup>,
) {
    (
        Some(super::build_sync_header(
            header::Commands::SessionSetup,
            1,
            8192,
            None,
            Some(session_id),
            2,
        )),
        Some(build_default_session_setup_authenticate_request_body(
            server_challenge_struct,
        )),
    )
}

/// Builds a working default session setup 2 request body.
pub fn build_default_session_setup_authenticate_request_body(
    server_challenge_struct: ntlmssp::challenge::Challenge,
) -> requests::session_setup::SessionSetup {
    let mut session_setup = requests::session_setup::SessionSetup::default();

    session_setup.flags = requests::session_setup::Flags::Zero.unpack_byte_code();
    session_setup.security_mode = fields::SecurityMode::NegotiateSigningEnabled.unpack_byte_code(1);
    session_setup.capabilities =
        requests::session_setup::Capabilities::GlobalCapDfs.unpack_byte_code();
    session_setup.channel = vec![0; 4];
    session_setup.security_buffer_offset = SECURITY_BUFFER_OFFSET.to_vec();
    session_setup.security_buffer_length = SECURITY_BUFFER_LENGTH.to_vec();
    session_setup.previous_session_id = vec![0; 8];
    session_setup.buffer = encode_security_authentication(
        security_buffer::build_session_setup_authenticate_request_security_buffer(
            server_challenge_struct,
        ),
    );

    session_setup
}

#[cfg(test)]
mod tests {}
