use crate::smb2::{
    helper_functions::{
        fields::SecurityMode,
        negotiate_context::{
            CompressionCapabilities, ContextType, EncryptionCapabilities, NegotiateContext,
            NetnameNegotiateContextId, PreauthIntegrityCapabilities, RdmaTransformCapabilities,
            TransportCapabilities,
        },
    },
    responses,
    responses::negotiate::DialectRevision,
};

use crate::format::{convert_byte_array_to_int, HEADER_LENGTH};

/// Decodes the the negotiate response.
pub fn decode_negotiate_response_body(encoded_body: Vec<u8>) -> responses::negotiate::Negotiate {
    let mut negotiate_response = responses::negotiate::Negotiate::default();

    negotiate_response.structure_size = encoded_body[..2].to_vec();
    negotiate_response.security_mode = Some(SecurityMode::map_byte_code_to_mode(
        encoded_body[2..4].to_vec(),
    ));
    negotiate_response.dialect_revision = Some(DialectRevision::map_byte_code_to_dialect(
        encoded_body[4..6].to_vec(),
    ));
    negotiate_response.negotiate_context_count = encoded_body[6..8].to_vec();
    negotiate_response.server_guid = encoded_body[8..24].to_vec();
    negotiate_response.capabilities = encoded_body[24..28].to_vec();
    negotiate_response.max_transact_size = encoded_body[28..32].to_vec();
    negotiate_response.max_read_size = encoded_body[32..36].to_vec();
    negotiate_response.max_write_size = encoded_body[36..40].to_vec();
    negotiate_response.system_time = encoded_body[40..48].to_vec();
    negotiate_response.server_start_time = encoded_body[48..56].to_vec();
    negotiate_response.security_buffer_offset = encoded_body[56..58].to_vec();
    negotiate_response.security_buffer_length = encoded_body[58..60].to_vec();
    negotiate_response.negotiate_context_offset = encoded_body[60..64].to_vec();

    let buffer_end_index = 64
        + convert_byte_array_to_int(negotiate_response.security_buffer_length.clone(), false)
            as usize;
    negotiate_response.buffer = encoded_body[64..buffer_end_index].to_vec();

    if let DialectRevision::Smb311 = negotiate_response.dialect_revision.clone().unwrap() {
        // The negotiate contexts need to be 8 byte aligned. Therefore, the optional padding size needs to be calculated from
        // from the index of the last buffer byte.
        let padding_end_index =
            convert_byte_array_to_int(negotiate_response.negotiate_context_offset.clone(), false)
                as usize
                - HEADER_LENGTH;
        negotiate_response.padding = encoded_body[buffer_end_index..padding_end_index].to_vec();

        negotiate_response.negotiate_context_list =
            decode_negotiate_response_context(encoded_body, &negotiate_response, padding_end_index);
    }

    negotiate_response
}

/// Decodes the negotiate contexts of the negotiate response.
pub fn decode_negotiate_response_context(
    encoded_body: Vec<u8>,
    negotiate_response: &responses::negotiate::Negotiate,
    start_index: usize,
) -> Vec<NegotiateContext> {
    let context_count =
        convert_byte_array_to_int(negotiate_response.negotiate_context_count.clone(), false);
    let mut context_list: Vec<NegotiateContext> = Vec::new();
    let mut current_context_offset = start_index;

    for _ in 0..context_count {
        let neg_context = decode_generic_context(&encoded_body, current_context_offset);
        // the context size is made up of the fields: (type, length, reserved) = 8 byte and data.
        let context_size =
            (convert_byte_array_to_int(neg_context.data_length.clone(), false) + 8) as usize;
        let next_context_offset_without_padding = current_context_offset + context_size;
        current_context_offset = next_context_offset_without_padding
            + calculate_alignment_padding(next_context_offset_without_padding);
        context_list.push(neg_context);
    }

    context_list
}

/// Calculates the padding size for 8 byte alignment.
pub fn calculate_alignment_padding(offset_without_padding: usize) -> usize {
    8 - offset_without_padding % 8
}

/// Creates a new generic negotiate context and deligates the specific handling of its type
/// to the subroutines.
pub fn decode_generic_context(encoded_body: &[u8], start_index: usize) -> NegotiateContext {
    let mut neg_context = NegotiateContext::default();
    neg_context.context_type = encoded_body[start_index..start_index + 2].to_vec();
    neg_context.data_length = encoded_body[start_index + 2..start_index + 4].to_vec();
    let context_type_struct =
        ContextType::map_byte_code_to_context_type(neg_context.context_type.clone());

    match context_type_struct {
        ContextType::PreauthIntegrityCapabilities(mut preauth) => {
            decode_preauth_context(&mut preauth, encoded_body, start_index + 8);
            neg_context.data = Some(ContextType::PreauthIntegrityCapabilities(preauth));
        }
        ContextType::EncryptionCapabilities(mut encrypt) => {
            decode_encryption_context(&mut encrypt, encoded_body, start_index + 8);
            neg_context.data = Some(ContextType::EncryptionCapabilities(encrypt));
        }
        ContextType::CompressionCapabilities(mut compress) => {
            decode_compression_context(&mut compress, encoded_body, start_index + 8);
            neg_context.data = Some(ContextType::CompressionCapabilities(compress));
        }
        ContextType::NetnameNegotiateContextId(mut netname) => {
            decode_netname_context(
                &mut netname,
                encoded_body,
                start_index + 8,
                neg_context.data_length.clone(),
            );
            neg_context.data = Some(ContextType::NetnameNegotiateContextId(netname));
        }
        ContextType::TransportCapabilities(mut transport) => {
            decode_transport_context(&mut transport, encoded_body, start_index + 8);
            neg_context.data = Some(ContextType::TransportCapabilities(transport));
        }
        ContextType::RdmaTransformCapabilities(mut rdma) => {
            decode_rdma_transform_context(&mut rdma, encoded_body, start_index + 8);
            neg_context.data = Some(ContextType::RdmaTransformCapabilities(rdma));
        }
    }

    neg_context
}

/// Decodes the PreauthIntegrityCapabilities.
pub fn decode_preauth_context(
    preauth_cap: &mut PreauthIntegrityCapabilities,
    encoded_body: &[u8],
    start_index: usize,
) {
    preauth_cap.salt_length = encoded_body[start_index + 2..start_index + 4].to_vec();
    let salt_length = convert_byte_array_to_int(preauth_cap.salt_length.clone(), false) as usize;
    preauth_cap.salt = encoded_body[start_index + 6..start_index + 6 + salt_length].to_vec();
}

/// Decodes the Encryption Capabilities.
pub fn decode_encryption_context(
    encrypt_cap: &mut EncryptionCapabilities,
    encoded_body: &[u8],
    start_index: usize,
) {
    encrypt_cap.cipher_count = encoded_body[start_index..start_index + 2].to_vec();
    let cipher_index = start_index + 2;
    for counter in 0..convert_byte_array_to_int(encrypt_cap.cipher_count.clone(), false) {
        encrypt_cap.ciphers.push(
            encoded_body
                [cipher_index + (2 * counter as usize)..cipher_index + 2 + (2 * counter as usize)]
                .to_vec(),
        );
    }
}

/// Decodes the Compression Capabilities.
pub fn decode_compression_context(
    compress_cap: &mut CompressionCapabilities,
    encoded_body: &[u8],
    start_index: usize,
) {
    compress_cap.compression_algorithm_count = encoded_body[start_index..start_index + 2].to_vec();
    compress_cap.padding = encoded_body[start_index + 2..start_index + 4].to_vec();
    compress_cap.flags = encoded_body[start_index + 4..start_index + 8].to_vec();
    let algo_index = start_index + 8;
    for counter in
        0..convert_byte_array_to_int(compress_cap.compression_algorithm_count.clone(), false)
    {
        compress_cap.compression_algorithms.push(
            encoded_body
                [algo_index + (2 * counter as usize)..algo_index + 2 + (2 * counter as usize)]
                .to_vec(),
        );
    }
}

/// Decodes the Netname Context Id.
pub fn decode_netname_context(
    netname: &mut NetnameNegotiateContextId,
    encoded_body: &[u8],
    start_index: usize,
    name_length_in_bytes: Vec<u8>,
) {
    let name_length = convert_byte_array_to_int(name_length_in_bytes, false) as usize;
    netname.net_name = encoded_body[start_index..name_length + start_index].to_vec();
}

/// Decodes the Transport Capabilities.
pub fn decode_transport_context(
    transport_cap: &mut TransportCapabilities,
    encoded_body: &[u8],
    start_index: usize,
) {
    transport_cap.reserved = encoded_body[start_index..start_index + 4].to_vec();
}

/// Decodes the RDMA Transform Capabilities
pub fn decode_rdma_transform_context(
    rdma_cap: &mut RdmaTransformCapabilities,
    encoded_body: &[u8],
    start_index: usize,
) {
    rdma_cap.transform_count = encoded_body[start_index..start_index + 2].to_vec();
    rdma_cap.reserved1 = encoded_body[start_index + 2..start_index + 4].to_vec();
    rdma_cap.reserved2 = encoded_body[start_index + 4..start_index + 8].to_vec();
    let id_index = start_index + 8;
    for counter in 0..convert_byte_array_to_int(rdma_cap.transform_count.clone(), false) {
        rdma_cap.rdma_transform_ids.push(
            encoded_body[id_index + (2 * counter as usize)..id_index + 2 + (2 * counter as usize)]
                .to_vec(),
        );
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_decode_negotiate_response_body() {
        let encoded_negotiate_response: Vec<u8> = vec![
            b"\x41\x00\x01\x00\x11\x03\x02\x00\x72\x61\x73\x70\x62\x65\x72\x72".to_vec(),
            b"\x79\x70\x69\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x80\x00".to_vec(),
            b"\x00\x00\x80\x00\x00\x00\x80\x00\x9e\xfb\x27\x7c\x52\x1e\xd7\x01".to_vec(),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x4a\x00\xd0\x00\x00\x00".to_vec(),
            b"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e".to_vec(),
            b"\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa3\x2a".to_vec(),
            b"\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f\x64\x65\x66\x69\x6e\x65".to_vec(),
            b"\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31\x37\x38\x40\x70\x6c\x65".to_vec(),
            b"\x61\x73\x65\x5f\x69\x67\x6e\x6f\x72\x65\x00\x00\x00\x00\x00\x00".to_vec(),
            b"\x01\x00\x26\x00\x00\x00\x00\x00\x01\x00\x20\x00\x01\x00\x8c\x24".to_vec(),
            b"\x4b\x62\x9b\x11\xba\x46\x2c\x73\x00\xeb\x9f\x9a\xf3\xfc\xc7\x3d".to_vec(),
            b"\xf4\x86\xb6\x8c\x5b\x4d\x7d\x61\xf0\x86\x1c\x1f\xaf\x90\x00\x00".to_vec(),
            b"\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x01\x00".to_vec(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let decoded_negotiate_response = decode_negotiate_response_body(encoded_negotiate_response);

        assert_eq!(vec![65, 0], decoded_negotiate_response.structure_size);

        assert_eq!(
            Some(SecurityMode::NegotiateSigningEnabled),
            decoded_negotiate_response.security_mode
        );

        assert_eq!(
            Some(DialectRevision::Smb311),
            decoded_negotiate_response.dialect_revision
        );

        assert_eq!(
            vec![2, 0],
            decoded_negotiate_response.negotiate_context_count
        );

        assert_eq!(
            vec![114, 97, 115, 112, 98, 101, 114, 114, 121, 112, 105, 0, 0, 0, 0, 0],
            decoded_negotiate_response.server_guid
        );

        assert_eq!(vec![7, 0, 0, 0], decoded_negotiate_response.capabilities);

        assert_eq!(
            vec![0, 0, 128, 0],
            decoded_negotiate_response.max_transact_size
        );

        assert_eq!(vec![0, 0, 128, 0], decoded_negotiate_response.max_read_size);

        assert_eq!(
            vec![0, 0, 128, 0],
            decoded_negotiate_response.max_write_size
        );

        assert_eq!(
            vec![158, 251, 39, 124, 82, 30, 215, 1],
            decoded_negotiate_response.system_time
        );

        assert_eq!(vec![0; 8], decoded_negotiate_response.server_start_time);

        assert_eq!(
            vec![128, 0],
            decoded_negotiate_response.security_buffer_offset
        );

        assert_eq!(
            vec![74, 0],
            decoded_negotiate_response.security_buffer_length
        );

        assert_eq!(
            vec![208, 0, 0, 0],
            decoded_negotiate_response.negotiate_context_offset
        );

        let security_blob = vec![
            96, 72, 6, 6, 43, 6, 1, 5, 5, 2, 160, 62, 48, 60, 160, 14, 48, 12, 6, 10, 43, 6, 1, 4,
            1, 130, 55, 2, 2, 10, 163, 42, 48, 40, 160, 38, 27, 36, 110, 111, 116, 95, 100, 101,
            102, 105, 110, 101, 100, 95, 105, 110, 95, 82, 70, 67, 52, 49, 55, 56, 64, 112, 108,
            101, 97, 115, 101, 95, 105, 103, 110, 111, 114, 101,
        ];

        assert_eq!(security_blob, decoded_negotiate_response.buffer);

        assert_eq!(vec![0, 0, 0, 0, 0, 0], decoded_negotiate_response.padding);

        let mut expected_preauth = PreauthIntegrityCapabilities::default();
        expected_preauth.hash_algorithm_count = vec![1, 0];
        expected_preauth.salt_length = vec![32, 0];
        expected_preauth.hash_algorithms = vec![vec![1, 0]];
        expected_preauth.salt = vec![
            140, 36, 75, 98, 155, 17, 186, 70, 44, 115, 0, 235, 159, 154, 243, 252, 199, 61, 244,
            134, 182, 140, 91, 77, 125, 97, 240, 134, 28, 31, 175, 144,
        ];

        let mut expected_negotiate_context = NegotiateContext::default();
        let mut expect_context_type = ContextType::PreauthIntegrityCapabilities(expected_preauth);

        expected_negotiate_context.context_type = expect_context_type.unpack_byte_code();
        expected_negotiate_context.data_length = vec![38, 0];
        expected_negotiate_context.reserved = vec![0; 4];
        expected_negotiate_context.data = Some(expect_context_type);

        assert_eq!(
            expected_negotiate_context,
            *decoded_negotiate_response
                .negotiate_context_list
                .get(0)
                .unwrap()
        );

        let mut expected_encryption = EncryptionCapabilities::default();
        expected_encryption.cipher_count = vec![1, 0];
        expected_encryption.ciphers = vec![vec![1, 0]];

        expect_context_type = ContextType::EncryptionCapabilities(expected_encryption);
        expected_negotiate_context.context_type = expect_context_type.unpack_byte_code();
        expected_negotiate_context.data_length = vec![4, 0];
        expected_negotiate_context.data = Some(expect_context_type);

        assert_eq!(
            expected_negotiate_context,
            *decoded_negotiate_response
                .negotiate_context_list
                .get(1)
                .unwrap()
        );
    }
}
