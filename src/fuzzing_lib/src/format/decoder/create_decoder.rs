use crate::smb2::responses;

/// Takes the little endian encoded create response from the server and populates the corresponding
/// Create Response struct.
pub fn decode_create_response_body(encoded_body: Vec<u8>) -> responses::create::Create {
    let mut create_response = responses::create::Create::default();

    create_response.structure_size = encoded_body[0..2].to_vec();
    create_response.op_lock_level = encoded_body[2..3].to_vec();
    create_response.flags = encoded_body[3..4].to_vec();
    create_response.create_action = encoded_body[4..8].to_vec();
    create_response.creation_time = encoded_body[8..16].to_vec();
    create_response.last_access_time = encoded_body[16..24].to_vec();
    create_response.last_write_time = encoded_body[24..32].to_vec();
    create_response.change_time = encoded_body[32..40].to_vec();
    create_response.allocation_size = encoded_body[40..48].to_vec();
    create_response.end_of_file = encoded_body[48..56].to_vec();
    create_response.file_attributes = encoded_body[56..60].to_vec();
    create_response.reserved = encoded_body[60..64].to_vec();
    create_response.file_id = encoded_body[64..80].to_vec();
    create_response.create_contexts_offset = encoded_body[80..84].to_vec();
    create_response.create_contexts_length = encoded_body[84..88].to_vec();
    create_response.buffer = encoded_body[88..].to_vec();

    create_response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_create_response_body() {
        let encoded_create_response =
            b"\x59\x00\x00\x00\x01\x00\x00\x00\xb4\x10\x04\xf4\x3e\x25\xd7\x01\
        \xb4\x10\x04\xf4\x3e\x25\xd7\x01\xb4\x10\x04\xf4\x3e\x25\xd7\x01\
        \xb4\x10\x04\xf4\x3e\x25\xd7\x01\x00\x00\x10\x00\x00\x00\x00\x00\
        \x0e\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\
        \x25\x96\x72\xb3\x00\x00\x00\x00\x26\xb0\x76\xe9\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00"
                .to_vec();

        let mut expected_create_response_struct = responses::create::Create::default();
        expected_create_response_struct.op_lock_level = vec![0];
        expected_create_response_struct.create_action = b"\x01\x00\x00\x00".to_vec();
        expected_create_response_struct.creation_time =
            b"\xb4\x10\x04\xf4\x3e\x25\xd7\x01".to_vec();
        expected_create_response_struct.last_access_time =
            b"\xb4\x10\x04\xf4\x3e\x25\xd7\x01".to_vec();
        expected_create_response_struct.last_write_time =
            b"\xb4\x10\x04\xf4\x3e\x25\xd7\x01".to_vec();
        expected_create_response_struct.change_time = b"\xb4\x10\x04\xf4\x3e\x25\xd7\x01".to_vec();
        expected_create_response_struct.allocation_size =
            b"\x00\x00\x10\x00\x00\x00\x00\x00".to_vec();
        expected_create_response_struct.end_of_file = b"\x0e\x00\x00\x00\x00\x00\x00\x00".to_vec();
        expected_create_response_struct.file_attributes = b"\x80\x00\x00\x00".to_vec();
        expected_create_response_struct.file_id =
            b"\x25\x96\x72\xb3\x00\x00\x00\x00\x26\xb0\x76\xe9\x00\x00\x00\x00".to_vec();
        expected_create_response_struct.create_contexts_offset = vec![0; 4];
        expected_create_response_struct.create_contexts_length = vec![0; 4];

        assert_eq!(
            expected_create_response_struct,
            decode_create_response_body(encoded_create_response)
        );
    }
}
