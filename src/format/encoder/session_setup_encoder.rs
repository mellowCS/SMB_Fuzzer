use crate::smb2::requests::session_setup::SessionSetup;

/// Serializes the session setup request body.
pub fn serialize_session_setup_request_body(request: &SessionSetup) -> Vec<u8> {
    let mut serialized_request: Vec<u8> = Vec::new();

    serialized_request.append(&mut request.structure_size.clone());
    serialized_request.append(&mut request.flags.clone());
    serialized_request.append(&mut request.security_mode.clone());
    serialized_request.append(&mut request.capabilities.clone());
    serialized_request.append(&mut request.channel.clone());
    serialized_request.append(&mut request.security_buffer_offset.clone());
    serialized_request.append(&mut request.security_buffer_length.clone());
    serialized_request.append(&mut request.previous_session_id.clone());
    serialized_request.append(&mut request.buffer.clone());

    serialized_request
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::builder::session_setup_1_request::INITIAL_SECURITY_BLOB;

    struct Setup {
        session_setup: SessionSetup,
    }

    impl Setup {
        pub fn new() -> Self {
            let mut session_setup = SessionSetup::default();

            session_setup.flags = vec![0];
            session_setup.security_mode = vec![1];
            session_setup.capabilities = b"\x01\x00\x00\x00".to_vec();
            session_setup.security_buffer_offset = b"\x58\x00".to_vec();
            session_setup.security_buffer_length = b"\x4a\x00".to_vec();
            session_setup.previous_session_id = vec![0; 8];
            session_setup.buffer = INITIAL_SECURITY_BLOB.to_vec();

            Setup { session_setup }
        }
    }

    #[test]
    fn test_serialize_session_setup_request_body() {
        let setup = Setup::new();

        let mut expected_byte_array = b"\x19\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\
                                            \x58\x00\x4a\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            .to_vec();
        expected_byte_array.append(&mut INITIAL_SECURITY_BLOB.to_vec());

        assert_eq!(
            expected_byte_array,
            serialize_session_setup_request_body(&setup.session_setup)
        );
    }
}
