use super::super::create_random_byte_array_of_predefined_length;
use super::super::create_random_byte_array_with_random_length;
use crate::builder::session_setup_authenticate_request::security_buffer;
use crate::format::encoder::security_blob_encoder::encode_security_authentication;
use crate::{
    ntlmssp,
    smb2::{
        helper_functions::fields::SecurityMode,
        requests::session_setup::{Capabilities, Flags, SessionSetup},
    },
};

const DEFAULT_INITIAL_BUFFER_OFFSET: &[u8; 2] = b"\x58\x00";
const DEFAULT_INITIAL_BUFFER_LENGTH: &[u8; 2] = b"\x4a\x00";

const DEFAULT_AUTH_BUFFER_OFFSET: &[u8; 2] = b"\x58\x00";
const DEFAULT_AUTH_BUFFER_LENGTH: &[u8; 2] = b"\x56\x01";

pub const INITIAL_SECURITY_BLOB: &[u8;74] = b"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\
                                             \x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\
                                             \x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x05\x02\
                                             \x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x28\x00\
                                             \x00\x00\x06\x01\x00\x00\x00\x00\x00\x0f";

/// Fuzzes the session setup 1 request with predefined values.
pub fn fuzz_session_setup_negotiate_with_predefined_values() -> SessionSetup {
    let mut session_setup_request = SessionSetup::default();

    session_setup_request.flags = rand::random::<Flags>().unpack_byte_code();
    session_setup_request.security_mode = rand::random::<SecurityMode>().unpack_byte_code(1);
    session_setup_request.capabilities = Capabilities::GlobalCapDfs.unpack_byte_code();
    session_setup_request.channel = vec![0; 4];
    session_setup_request.security_buffer_offset = DEFAULT_INITIAL_BUFFER_OFFSET.to_vec();
    session_setup_request.security_buffer_length = DEFAULT_INITIAL_BUFFER_LENGTH.to_vec();
    session_setup_request.buffer = INITIAL_SECURITY_BLOB.to_vec();
    session_setup_request.previous_session_id = vec![0; 8];

    session_setup_request
}

/// Fuzzes the session setup 2 request with predefined values.
pub fn fuzz_session_setup_authenticate_with_predefined_values(
    server_challenge_struct: ntlmssp::challenge::Challenge,
) -> SessionSetup {
    let mut session_setup_request = SessionSetup::default();

    session_setup_request.flags = rand::random::<Flags>().unpack_byte_code();
    session_setup_request.security_mode = rand::random::<SecurityMode>().unpack_byte_code(1);
    session_setup_request.capabilities = Capabilities::GlobalCapDfs.unpack_byte_code();
    session_setup_request.channel = vec![0; 4];
    session_setup_request.security_buffer_offset = DEFAULT_AUTH_BUFFER_OFFSET.to_vec();
    session_setup_request.security_buffer_length = DEFAULT_AUTH_BUFFER_LENGTH.to_vec();
    session_setup_request.previous_session_id = vec![0; 8];
    session_setup_request.buffer = encode_security_authentication(
        security_buffer::build_session_setup_authenticate_request_security_buffer(
            server_challenge_struct,
        ),
    );

    session_setup_request
}

/// Fuzz the session setup authenticate request with random fields with the size complying to the specifications.
pub fn fuzz_session_setup_with_random_fields() -> SessionSetup {
    let mut session_setup_request = SessionSetup::default();

    session_setup_request.structure_size = create_random_byte_array_of_predefined_length(2);
    session_setup_request.flags = create_random_byte_array_of_predefined_length(1);
    session_setup_request.security_mode = create_random_byte_array_of_predefined_length(1);
    session_setup_request.capabilities = create_random_byte_array_of_predefined_length(4);
    session_setup_request.channel = create_random_byte_array_of_predefined_length(4);
    session_setup_request.security_buffer_offset = create_random_byte_array_of_predefined_length(2);
    session_setup_request.security_buffer_length = create_random_byte_array_of_predefined_length(2);
    session_setup_request.buffer = create_random_byte_array_with_random_length();
    session_setup_request.previous_session_id = create_random_byte_array_of_predefined_length(2);

    session_setup_request
}

/// Fuzz the session setup authenticate request with random fields of random size.
pub fn fuzz_session_setup_completely_random() -> SessionSetup {
    let mut session_setup_request = SessionSetup::default();

    session_setup_request.structure_size = create_random_byte_array_with_random_length();
    session_setup_request.flags = create_random_byte_array_with_random_length();
    session_setup_request.security_mode = create_random_byte_array_with_random_length();
    session_setup_request.capabilities = create_random_byte_array_with_random_length();
    session_setup_request.channel = create_random_byte_array_with_random_length();
    session_setup_request.security_buffer_offset = create_random_byte_array_with_random_length();
    session_setup_request.security_buffer_length = create_random_byte_array_with_random_length();
    session_setup_request.buffer = create_random_byte_array_with_random_length();
    session_setup_request.previous_session_id = create_random_byte_array_with_random_length();

    session_setup_request
}
