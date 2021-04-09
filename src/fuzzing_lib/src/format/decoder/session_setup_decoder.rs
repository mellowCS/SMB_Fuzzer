use crate::smb2::responses;

/// Decodes the little endian encoded session setup response from the server.
///
/// Note: The security buffer is decoded separately.
pub fn decode_session_setup_response_body(
    encoded_body: Vec<u8>,
) -> responses::session_setup::SessionSetup {
    let mut session_setup_response = responses::session_setup::SessionSetup::default();

    session_setup_response.structure_size = encoded_body[..2].to_vec();
    session_setup_response.session_flags = Some(
        responses::session_setup::SessionFlags::map_byte_code_to_session_flags(
            encoded_body[2..4].to_vec(),
        ),
    );
    session_setup_response.security_buffer_offset = encoded_body[4..6].to_vec();
    session_setup_response.security_buffer_length = encoded_body[6..8].to_vec();
    session_setup_response.buffer = encoded_body[8..].to_vec();

    session_setup_response
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_decode_session_setup_response_body() {
        let mut encoded_session_response_body: Vec<u8> =
            b"\x09\x00\x00\x00\x48\x00\xd1\x00".to_vec();
        let security_blob: Vec<u8> = b"\xa1\x81\
        \xce\x30\x81\xcb\xa0\x03\x0a\x01\x01\xa1\x0c\x06\x0a\x2b\x06\x01\
        \x04\x01\x82\x37\x02\x02\x0a\xa2\x81\xb5\x04\x81\xb2\x4e\x54\x4c\
        \x4d\x53\x53\x50\x00\x02\x00\x00\x00\x16\x00\x16\x00\x38\x00\x00\
        \x00\x15\x82\x8a\x62\x8d\x51\x0b\x30\x2d\x45\x71\xe0\x00\x00\x00\
        \x00\x00\x00\x00\x00\x64\x00\x64\x00\x4e\x00\x00\x00\x06\x01\x00\
        \x00\x00\x00\x00\x0f\x52\x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\
        \x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00\x02\x00\x16\x00\x52\
        \x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\x00\x52\x00\x52\x00\x59\
        \x00\x50\x00\x49\x00\x01\x00\x16\x00\x52\x00\x41\x00\x53\x00\x50\
        \x00\x42\x00\x45\x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00\x04\
        \x00\x02\x00\x00\x00\x03\x00\x16\x00\x72\x00\x61\x00\x73\x00\x70\
        \x00\x62\x00\x65\x00\x72\x00\x72\x00\x79\x00\x70\x00\x69\x00\x07\
        \x00\x08\x00\x60\x16\xad\x6d\x47\x21\xd7\x01\x00\x00\x00\x00"
            .to_vec();

        encoded_session_response_body.append(&mut security_blob.clone());

        let mut expected_response = responses::session_setup::SessionSetup::default();
        expected_response.session_flags = Some(responses::session_setup::SessionFlags::Zero);
        expected_response.security_buffer_offset = b"\x48\x00".to_vec();
        expected_response.security_buffer_length = b"\xd1\x00".to_vec();
        expected_response.buffer = security_blob;

        assert_eq!(
            expected_response,
            decode_session_setup_response_body(encoded_session_response_body)
        );
    }
}
