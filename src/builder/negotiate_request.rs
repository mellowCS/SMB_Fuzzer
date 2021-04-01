use crate::smb2::{
    header,
    helper_functions::{
        fields,
        negotiate_context::{
            Ciphers, CompressionAlgorithms, CompressionCapabilities, ContextType,
            EncryptionCapabilities, NegotiateContext, NetnameNegotiateContextId,
            PreauthIntegrityCapabilities,
        },
    },
    requests::{self, negotiate::Dialects},
};

pub const DEFAULT_DIALECT_COUNT: &[u8; 2] = b"\x05\x00";
pub const ALL_EXCEPT_ENCRYPTION: &[u8; 4] = b"\x3f\x00\x00\x00";
pub const DEFAULT_CONTEXT_OFFSET: &[u8; 4] = b"\x70\x00\x00\x00";

/// Builds the working default negotiate request.
pub fn build_default_negotiate_request() -> (header::SyncHeader, requests::negotiate::Negotiate) {
    let mut neg_req = requests::negotiate::Negotiate::default();

    neg_req.dialect_count = DEFAULT_DIALECT_COUNT.to_vec();
    neg_req.security_mode = fields::SecurityMode::NegotiateSigningEnabled.unpack_byte_code(2);
    neg_req.capabilities = ALL_EXCEPT_ENCRYPTION.to_vec();
    neg_req.client_guid = vec![0; 16];

    neg_req.dialects = build_default_dialect_list();
    neg_req.padding = vec![0; 2];

    neg_req.negotiate_context_list = build_default_negotiate_context_list();
    neg_req.negotiate_context_count = (neg_req.negotiate_context_list.len() as u16)
        .to_le_bytes()
        .to_vec();
    neg_req.negotiate_context_offset = DEFAULT_CONTEXT_OFFSET.to_vec();

    (
        super::build_sync_header(header::Commands::Negotiate, 0, 0, None, None, 0),
        neg_req,
    )
}

/// Builds the working default dialect list.
pub fn build_default_dialect_list() -> Vec<Vec<u8>> {
    vec![
        Dialects::Smb202.unpack_byte_code(),
        Dialects::Smb21.unpack_byte_code(),
        Dialects::Smb30.unpack_byte_code(),
        Dialects::Smb302.unpack_byte_code(),
        Dialects::Smb311.unpack_byte_code(),
    ]
}

/// Builds the negotiate context list according to the given parameters.
pub fn build_default_negotiate_context_list() -> Vec<NegotiateContext> {
    vec![
        build_default_preauthentication_context(),
        build_default_compression_context(),
        build_default_netname_context_id(),
    ]
}

/// Builds the working default preauthentication context.
pub fn build_default_preauthentication_context() -> NegotiateContext {
    let mut preauth = NegotiateContext::default();
    let mut preauth_caps = PreauthIntegrityCapabilities::default();

    preauth_caps.hash_algorithm_count = b"\x01\x00".to_vec();
    preauth_caps.salt_length = b"\x20\x00".to_vec();
    preauth_caps.hash_algorithms = vec![b"\x01\x00".to_vec()];
    preauth_caps.salt =
        b"\x79\x13\x02\xd4\xd7\x0c\x2a\x12\x50\x84\xba\xa6\x03\xae\xda\xe4\x12\xe8\x0b\x6e\
                          \x96\xf7\xdb\xa9\x46\xdf\x3e\xdc\x16\xe8\x4a\x5a"
            .to_vec();

    let preauth_context = ContextType::PreauthIntegrityCapabilities(preauth_caps);

    preauth.context_type = preauth_context.unpack_byte_code();
    preauth.data_length = b"\x26\x00".to_vec();
    preauth.data = Some(preauth_context);

    preauth
}

/// Builds the working default encryption negotiate context.
pub fn build_default_encryption_context() -> NegotiateContext {
    // TODO: add option to pass cipher selection.
    let mut encrypt = NegotiateContext::default();
    let mut encrypt_caps = EncryptionCapabilities::default();

    encrypt_caps.cipher_count = b"\x02\x00".to_vec();
    encrypt_caps.ciphers = vec![
        Ciphers::Aes128Gcm.unpack_byte_code(),
        Ciphers::Aes128Ccm.unpack_byte_code(),
    ];

    let encrypt_context = ContextType::EncryptionCapabilities(encrypt_caps);

    encrypt.context_type = encrypt_context.unpack_byte_code();
    encrypt.data_length = b"\x06\x00".to_vec();
    encrypt.data = Some(encrypt_context);

    encrypt
}

/// Builds the working default compression context.
pub fn build_default_compression_context() -> NegotiateContext {
    // TODO: add selection option for compression algorithms.
    let mut compress = NegotiateContext::default();
    let mut compress_caps = CompressionCapabilities::default();

    compress_caps.compression_algorithm_count = b"\x03\x00".to_vec();
    compress_caps.flags = vec![0; 4];
    compress_caps.compression_algorithms = vec![
        CompressionAlgorithms::Lz77.unpack_byte_code(),
        CompressionAlgorithms::Lz77Huffman.unpack_byte_code(),
        CompressionAlgorithms::Lznt1.unpack_byte_code(),
    ];

    let compress_context = ContextType::CompressionCapabilities(compress_caps);

    compress.context_type = compress_context.unpack_byte_code();
    compress.data_length = b"\x0e\x00".to_vec();
    compress.data = Some(compress_context);

    compress
}

/// Builds the working default netname context id.
pub fn build_default_netname_context_id() -> NegotiateContext {
    // TODO: add option to choose netname.
    let mut netname = NegotiateContext::default();
    let mut netname_id = NetnameNegotiateContextId::default();

    netname_id.net_name = b"\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38\
                            \x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x37\x00\x31\x00"
        .to_vec();

    let netname_context = ContextType::NetnameNegotiateContextId(netname_id);

    netname.context_type = netname_context.unpack_byte_code();
    netname.data_length = b"\x1a\x00".to_vec();
    netname.data = Some(netname_context);

    netname
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_build_default_negotiate_request() {}

    #[test]
    fn test_build_default_preauthentication_context() {}

    #[test]
    fn test_build_default_encryption_context() {}

    #[test]
    fn test_build_default_compression_context() {}

    #[test]
    fn test_build_default_netname_context_id() {}
}
