use crate::smb2::{
    helper_functions::negotiate_context::{
        CompressionCapabilities, ContextType, EncryptionCapabilities, NegotiateContext,
        NetnameNegotiateContextId, PreauthIntegrityCapabilities, RDMATransformCapabilities,
        TransportCapabilities,
    },
    requests::negotiate::Negotiate,
};

use crate::format::convert_byte_array_to_int;

/// Serializes a negotiate request from the corresponding struct.
pub fn serialize_negotiate_request_body(request: &Negotiate) -> Vec<u8> {
    let mut serialized_request: Vec<u8> = Vec::new();

    serialized_request.append(&mut request.structure_size.clone());
    serialized_request.append(&mut request.dialect_count.clone());
    serialized_request.append(&mut request.security_mode.clone());
    serialized_request.append(&mut request.reserved.clone());
    serialized_request.append(&mut request.capabilities.clone());
    serialized_request.append(&mut request.client_guid.clone());
    serialized_request.append(&mut request.negotiate_context_offset.clone());
    serialized_request.append(&mut request.negotiate_context_count.clone());
    serialized_request.append(&mut request.reserved2.clone());
    serialized_request.append(&mut request.dialects.iter().cloned().flatten().collect());
    serialized_request.append(&mut request.padding.clone());
    serialized_request.append(&mut serialize_negotiate_contexts(
        request.negotiate_context_list.clone(),
    ));

    serialized_request
}

/// Serializes the list of negotiate contexts.
pub fn serialize_negotiate_contexts(context_list: Vec<NegotiateContext>) -> Vec<u8> {
    let mut serialized_negotiate_contexts: Vec<u8> = Vec::new();
    let context_list_length = context_list.len() as usize;
    for (index, context) in context_list.into_iter().enumerate() {
        serialized_negotiate_contexts.append(&mut context.context_type.clone());
        serialized_negotiate_contexts.append(&mut context.data_length.clone());
        serialized_negotiate_contexts.append(&mut context.reserved.clone());
        serialized_negotiate_contexts.append(&mut navigate_to_corresponding_serializer(
            &context.data.unwrap(),
        ));
        if index < context_list_length - 1 {
            serialized_negotiate_contexts
                .append(&mut add_alignment_padding_if_necessary(context.data_length));
        }
    }

    serialized_negotiate_contexts
}

/// Adds an alignment padding between negotiate contexts if the data length is not 8 byte aligned.
pub fn add_alignment_padding_if_necessary(data_length: Vec<u8>) -> Vec<u8> {
    vec![0; (8 - convert_byte_array_to_int(data_length, false) % 8) as usize]
}

/// Navigates to a different serializer depending on the given context type.
pub fn navigate_to_corresponding_serializer(context_type: &ContextType) -> Vec<u8> {
    match context_type {
        ContextType::PreauthIntegrityCapabilities(preauth) => {
            serialize_preauth_capabilities(preauth)
        }
        ContextType::EncryptionCapabilities(encryption) => {
            serialize_encryption_capabilities(encryption)
        }
        ContextType::CompressionCapabilities(compression) => {
            serialize_compression_capabilities(compression)
        }
        ContextType::NetnameNegotiateContextId(netname) => serialize_netname_context_id(netname),
        ContextType::TransportCapabilities(transport) => {
            serialize_transport_capabilities(transport)
        }
        ContextType::RDMATransformCapabilities(rdma) => serialize_rdma_transform_capabilities(rdma),
    }
}

/// Serializes pre authentication capabilities.
pub fn serialize_preauth_capabilities(preauth: &PreauthIntegrityCapabilities) -> Vec<u8> {
    let mut serialized_preauth: Vec<u8> = Vec::new();

    serialized_preauth.append(&mut preauth.hash_algorithm_count.clone());
    serialized_preauth.append(&mut preauth.salt_length.clone());
    serialized_preauth.append(&mut preauth.hash_algorithms.iter().cloned().flatten().collect());
    serialized_preauth.append(&mut preauth.salt.clone());

    serialized_preauth
}

/// Serializes encryption capabilities.
pub fn serialize_encryption_capabilities(encryption: &EncryptionCapabilities) -> Vec<u8> {
    let mut serialized_encryption: Vec<u8> = Vec::new();

    serialized_encryption.append(&mut encryption.cipher_count.clone());
    serialized_encryption.append(&mut encryption.ciphers.iter().cloned().flatten().collect());

    serialized_encryption
}

/// Serializes compression capabilities.
pub fn serialize_compression_capabilities(compression: &CompressionCapabilities) -> Vec<u8> {
    let mut serialized_compression: Vec<u8> = Vec::new();

    serialized_compression.append(&mut compression.compression_algorithm_count.clone());
    serialized_compression.append(&mut compression.padding.clone());
    serialized_compression.append(&mut compression.flags.clone());
    serialized_compression.append(
        &mut compression
            .compression_algorithms
            .iter()
            .cloned()
            .flatten()
            .collect(),
    );

    serialized_compression
}

/// Serializes the netname context id.
pub fn serialize_netname_context_id(netname: &NetnameNegotiateContextId) -> Vec<u8> {
    netname.net_name.clone()
}

/// Serializes transport capabilities.
pub fn serialize_transport_capabilities(transport: &TransportCapabilities) -> Vec<u8> {
    transport.reserved.clone()
}

/// Serializes rdma transform capabilities.
pub fn serialize_rdma_transform_capabilities(rdma: &RDMATransformCapabilities) -> Vec<u8> {
    let mut serialized_rdma_transform: Vec<u8> = Vec::new();

    serialized_rdma_transform.append(&mut rdma.transform_count.clone());
    serialized_rdma_transform.append(&mut rdma.reserved1.clone());
    serialized_rdma_transform.append(&mut rdma.reserved2.clone());
    serialized_rdma_transform
        .append(&mut rdma.rdma_transform_ids.iter().cloned().flatten().collect());

    serialized_rdma_transform
}

#[cfg(test)]
mod tests {

    use crate::smb2::{
        helper_functions::fields::Capabilities,
        helper_functions::{fields, negotiate_context},
        requests,
    };

    use super::*;

    struct Setup {
        preauth: PreauthIntegrityCapabilities,
        encrypt: EncryptionCapabilities,
        compress: CompressionCapabilities,
        netname: NetnameNegotiateContextId,
        transport: TransportCapabilities,
        rdma: RDMATransformCapabilities,
        negotiate_context_encrypt: NegotiateContext,
        negotiate_context_compress: NegotiateContext,
    }

    impl Setup {
        pub fn new() -> Self {
            let mut preauth = PreauthIntegrityCapabilities::default();
            preauth.hash_algorithm_count = b"\x01\x00".to_vec();
            preauth.salt_length = b"\x20\x00".to_vec();
            preauth.hash_algorithms = vec![b"\x01\x00".to_vec()];
            preauth.salt =
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".to_vec();
            preauth.salt.append(
                &mut b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f".to_vec(),
            );

            let mut encrypt = EncryptionCapabilities::default();
            encrypt.cipher_count = b"\x01\x00".to_vec();
            encrypt.ciphers = vec![b"\x04\x00".to_vec()];

            let mut compress = CompressionCapabilities::default();
            compress.compression_algorithm_count = b"\x03\x00".to_vec();
            compress.padding = vec![0; 2];
            compress.flags =
                negotiate_context::Flags::CompressionCapabilitiesFlagNone.unpack_byte_code();
            compress.compression_algorithms = vec![
                negotiate_context::CompressionAlgorithms::LZNT1.unpack_byte_code(),
                negotiate_context::CompressionAlgorithms::LZ77.unpack_byte_code(),
                negotiate_context::CompressionAlgorithms::LZ77Huffman.unpack_byte_code(),
            ];

            let mut netname = NetnameNegotiateContextId::default();
            netname.net_name = b"\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38\x00\x2e\x00\x31\x00\x37\x00\x31\x00".to_vec();

            let mut rdma = RDMATransformCapabilities::default();
            rdma.transform_count = b"\x01\x00".to_vec();
            rdma.rdma_transform_ids =
                vec![negotiate_context::RDMATransformIds::RDMATransformNone.unpack_byte_code()];

            let mut negotiate_context_encrypt = NegotiateContext::default();
            let encrypt_context = ContextType::EncryptionCapabilities(encrypt.clone());
            negotiate_context_encrypt.context_type = encrypt_context.unpack_byte_code();
            negotiate_context_encrypt.data_length = b"\x04\x00".to_vec();
            negotiate_context_encrypt.data = Some(encrypt_context);

            let mut negotiate_context_compress = NegotiateContext::default();
            let compress_context = ContextType::CompressionCapabilities(compress.clone());
            negotiate_context_compress.context_type = compress_context.unpack_byte_code();
            negotiate_context_compress.data_length = b"\x0e\x00".to_vec();
            negotiate_context_compress.data = Some(compress_context);

            Setup {
                preauth,
                encrypt,
                compress,
                netname,
                transport: TransportCapabilities::default(),
                rdma,
                negotiate_context_encrypt,
                negotiate_context_compress,
            }
        }
    }

    #[test]
    fn test_serialize_negotiate_request_body() {
        let setup = Setup::new();

        let mut negotiate_request = requests::negotiate::Negotiate::default();
        negotiate_request.dialect_count = vec![1, 0];
        negotiate_request.security_mode =
            fields::SecurityMode::NegotiateSigningEnabled.unpack_byte_code(2);
        negotiate_request.capabilities = Capabilities::return_all_capabilities();
        negotiate_request.client_guid = vec![0; 16];
        negotiate_request.negotiate_context_offset = b"\x62\x00\x00\x00".to_vec();
        negotiate_request.negotiate_context_count = vec![2, 0];
        negotiate_request
            .dialects
            .push(requests::negotiate::Dialects::SMB311.unpack_byte_code());
        negotiate_request.padding = vec![0; 2];
        negotiate_request.negotiate_context_list = vec![
            setup.negotiate_context_encrypt,
            setup.negotiate_context_compress,
        ];

        let mut expected_byte_array = b"\x24\x00\x01\x00\x01\x00\x00\x00\x7f\x00\x00\x00".to_vec();
        expected_byte_array.append(&mut vec![0; 16]);
        expected_byte_array
            .append(&mut b"\x62\x00\x00\x00\x02\x00\x00\x00\x11\x03\x00\x00".to_vec());
        expected_byte_array.append(
            &mut b"\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00".to_vec(),
        );
        expected_byte_array.append(&mut b"\x03\x00\x0e\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x03\x00".to_vec());

        assert_eq!(
            expected_byte_array,
            serialize_negotiate_request_body(&negotiate_request)
        );
    }

    #[test]
    fn test_serialize_negotiate_contexts() {
        let setup = Setup::new();

        let expected_byte_array = b"\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x04\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            serialize_negotiate_contexts(vec![setup.negotiate_context_encrypt.clone()])
        );

        let expected_byte_array = b"\x03\x00\x0e\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x03\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            serialize_negotiate_contexts(vec![setup.negotiate_context_compress.clone()])
        );

        let mut expected_byte_array =
            b"\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00".to_vec();
        expected_byte_array.append(&mut b"\x03\x00\x0e\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x03\x00".to_vec());

        assert_eq!(
            expected_byte_array,
            serialize_negotiate_contexts(vec![
                setup.negotiate_context_encrypt,
                setup.negotiate_context_compress
            ])
        );
    }

    #[test]
    fn test_navigate_to_corresponding_serializer() {
        let setup = Setup::new();

        let mut expected_byte_array = b"\x01\x00\x04\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            navigate_to_corresponding_serializer(&ContextType::EncryptionCapabilities(
                setup.encrypt
            ))
        );

        expected_byte_array = b"\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x03\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            navigate_to_corresponding_serializer(&ContextType::CompressionCapabilities(
                setup.compress
            ))
        );
    }

    #[test]
    fn test_serialize_preauth_capabilities() {
        let setup = Setup::new();

        let mut expected_byte_array = b"\x01\x00\x20\x00\x01\x00".to_vec();
        expected_byte_array.append(
            &mut b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".to_vec(),
        );
        expected_byte_array.append(
            &mut b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f".to_vec(),
        );

        assert_eq!(
            expected_byte_array,
            serialize_preauth_capabilities(&setup.preauth)
        );
    }

    #[test]
    fn test_serialize_encryption_capabilities() {
        let setup = Setup::new();

        let expected_byte_array = b"\x01\x00\x04\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            serialize_encryption_capabilities(&setup.encrypt)
        );
    }

    #[test]
    fn test_serialize_compression_capabilities() {
        let setup = Setup::new();

        let expected_byte_array =
            b"\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x03\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            serialize_compression_capabilities(&setup.compress)
        );
    }

    #[test]
    fn test_serialize_netname_context_id() {
        let setup = Setup::new();

        let expected_byte_array = b"\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38\x00\x2e\x00\x31\x00\x37\x00\x31\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            serialize_netname_context_id(&setup.netname)
        );
    }

    #[test]
    fn test_serialize_transport_capabilities() {
        let setup = Setup::new();

        let expected_byte_array = vec![0; 4];

        assert_eq!(
            expected_byte_array,
            serialize_transport_capabilities(&setup.transport)
        );
    }

    #[test]
    fn test_serialize_rdma_transform_capabilities() {
        let setup = Setup::new();

        let expected_byte_array = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();

        assert_eq!(
            expected_byte_array,
            serialize_rdma_transform_capabilities(&setup.rdma)
        );
    }
}
