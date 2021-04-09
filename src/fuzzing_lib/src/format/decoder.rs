use crate::smb2::{header, responses};

use crate::format::{decoder::negotiate_decoder::decode_negotiate_response_body, HEADER_LENGTH};

use self::session_setup_decoder::decode_session_setup_response_body;

pub mod create_decoder;
pub mod negotiate_decoder;
pub mod security_blob_decoder;
pub mod session_setup_decoder;

/// Decodes the complete negotiate response from the server.
pub fn decode_negotiate_response(
    encoded_response: Vec<u8>,
) -> (header::SyncHeader, responses::negotiate::Negotiate) {
    (
        decode_response_header(encoded_response[4..HEADER_LENGTH + 4].to_vec()),
        decode_negotiate_response_body(encoded_response[HEADER_LENGTH + 4..].to_vec()),
    )
}

/// Decodes the complete session setup response from the server.
pub fn decode_session_setup_response(
    encoded_response: Vec<u8>,
) -> (header::SyncHeader, responses::session_setup::SessionSetup) {
    (
        decode_response_header(encoded_response[4..HEADER_LENGTH + 4].to_vec()),
        decode_session_setup_response_body(encoded_response[HEADER_LENGTH + 4..].to_vec()),
    )
}

/// Decodes the SMB Sync Header of server responses.
pub fn decode_response_header(encoded_header: Vec<u8>) -> header::SyncHeader {
    let mut response_header = header::SyncHeader::default();

    response_header.generic.protocol_id = encoded_header[..4].to_vec();
    response_header.generic.structure_size = encoded_header[4..6].to_vec();
    response_header.generic.credit_charge = encoded_header[6..8].to_vec();
    response_header.generic.status = encoded_header[8..12].to_vec();
    response_header.generic.command = encoded_header[12..14].to_vec();
    response_header.generic.credit = encoded_header[14..16].to_vec();
    response_header.generic.flags = encoded_header[16..20].to_vec();
    response_header.generic.next_command = encoded_header[20..24].to_vec();
    response_header.generic.message_id = encoded_header[24..32].to_vec();
    response_header.tree_id = encoded_header[36..40].to_vec();
    response_header.session_id = encoded_header[40..48].to_vec();
    response_header.signature = encoded_header[48..64].to_vec();

    response_header
}

#[cfg(test)]
mod tests {
    use super::super::convert_byte_array_to_int;
    use super::*;
    use crate::smb2::header::SyncHeader;

    // Netbios prefix: b"\x00\x00\x01\x0c".to_vec();

    #[test]
    fn test_decode_response_header() {
        let encoded_header: Vec<u8> = vec![
            b"\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00".to_vec(),
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let decoded_header: SyncHeader = decode_response_header(encoded_header);

        assert_eq!(vec![254, 83, 77, 66], decoded_header.generic.protocol_id);

        assert_eq!(
            64,
            convert_byte_array_to_int(decoded_header.generic.structure_size, false)
        );

        assert_eq!(vec![0, 0], decoded_header.generic.credit_charge);

        assert_eq!(vec![0; 4], decoded_header.generic.status);

        assert_eq!(vec![0, 0], decoded_header.generic.command);

        assert_eq!(vec![1, 0], decoded_header.generic.credit);

        assert_eq!(vec![1, 0, 0, 0], decoded_header.generic.flags);

        assert_eq!(vec![0; 4], decoded_header.generic.next_command);

        assert_eq!(vec![0; 8], decoded_header.generic.message_id);

        assert_eq!(vec![0; 4], decoded_header.reserved);

        assert_eq!(vec![0; 4], decoded_header.tree_id);

        assert_eq!(vec![0; 8], decoded_header.session_id);

        assert_eq!(vec![0; 16], decoded_header.signature);
    }
}
