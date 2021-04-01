//! This module describes the negotiate contexts.
//! The SMB2_NEGOTIATE_CONTEXT structure is used by the SMB2 NEGOTIATE Request
//! and the SMB2 NEGOTIATE Response to encode additional properties.
//! The server MUST support receiving negotiate contexts in any order.

/// ContextType (2 bytes): Specifies the type of context in the Data field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContextType {
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities),
    EncryptionCapabilities(EncryptionCapabilities),
    CompressionCapabilities(CompressionCapabilities),
    NetnameNegotiateContextId(NetnameNegotiateContextId),
    TransportCapabilities(TransportCapabilities),
    RdmaTransformCapabilities(RdmaTransformCapabilities),
}

impl ContextType {
    /// Unpacks the byte code for the context type.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            ContextType::PreauthIntegrityCapabilities(_) => b"\x01\x00".to_vec(),
            ContextType::EncryptionCapabilities(_) => b"\x02\x00".to_vec(),
            ContextType::CompressionCapabilities(_) => b"\x03\x00".to_vec(),
            ContextType::NetnameNegotiateContextId(_) => b"\x05\x00".to_vec(),
            ContextType::TransportCapabilities(_) => b"\x06\x00".to_vec(),
            ContextType::RdmaTransformCapabilities(_) => b"\x07\x00".to_vec(),
        }
    }

    /// Maps the byte code of an incoming response to the corresponding context type.
    pub fn map_byte_code_to_context_type(byte_code: Vec<u8>) -> ContextType {
        if let Some(code) = byte_code.get(0) {
            match code {
                1 => ContextType::PreauthIntegrityCapabilities(
                    PreauthIntegrityCapabilities::default(),
                ),
                2 => ContextType::EncryptionCapabilities(EncryptionCapabilities::default()),
                3 => ContextType::CompressionCapabilities(CompressionCapabilities::default()),
                5 => ContextType::NetnameNegotiateContextId(NetnameNegotiateContextId::default()),
                6 => ContextType::TransportCapabilities(TransportCapabilities::default()),
                7 => ContextType::RdmaTransformCapabilities(RdmaTransformCapabilities::default()),
                _ => panic!("Invalid context type in parsed response."),
            }
        } else {
            panic!("Empty context type in parsed response.")
        }
    }

    pub fn unpack_preauth_integrity(&self) -> PreauthIntegrityCapabilities {
        match self {
            ContextType::PreauthIntegrityCapabilities(pre) => pre.clone(),
            _ => panic!("Tried to unpack invalid Context Type."),
        }
    }

    pub fn unpack_encryption(&self) -> EncryptionCapabilities {
        match self {
            ContextType::EncryptionCapabilities(enc) => enc.clone(),
            _ => panic!("Tried to unpack invalid Context Type."),
        }
    }

    pub fn unpack_compression(&self) -> CompressionCapabilities {
        match self {
            ContextType::CompressionCapabilities(comp) => comp.clone(),
            _ => panic!("Tried to unpack invalid Context Type."),
        }
    }

    pub fn unpack_netname(&self) -> NetnameNegotiateContextId {
        match self {
            ContextType::NetnameNegotiateContextId(net) => net.clone(),
            _ => panic!("Tried to unpack invalid Context Type."),
        }
    }

    pub fn unpack_transport(&self) -> TransportCapabilities {
        match self {
            ContextType::TransportCapabilities(trans) => trans.clone(),
            _ => panic!("Tried to unpack invalid Context Type."),
        }
    }

    pub fn unpack_rdma_tansform(&self) -> RdmaTransformCapabilities {
        match self {
            ContextType::RdmaTransformCapabilities(rdma) => rdma.clone(),
            _ => panic!("Tried to unpack invalid Context Type."),
        }
    }
}

/// The SMB2_NEGOTIATE_CONTEXT structure is used by the SMB2 NEGOTIATE Request
/// and the SMB2 NEGOTIATE Response to encode additional properties.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NegotiateContext {
    /// ContextType (2 bytes): Specifies the type of context in the Data field.
    pub context_type: Vec<u8>,
    /// DataLength (2 bytes): The length, in bytes, of the Data field.
    pub data_length: Vec<u8>,
    /// Reserved (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// This value MUST be set to 0 by the client, and MUST be ignored by the server.
    pub reserved: Vec<u8>,
    /// Data (variable): A variable-length field that contains
    /// the negotiate context specified by the ContextType field.
    pub data: Option<ContextType>,
}

impl NegotiateContext {
    /// Creates a new instance of the Negotiate Context.
    pub fn default() -> Self {
        NegotiateContext {
            context_type: Vec::new(),
            data_length: Vec::new(),
            reserved: vec![0; 4],
            data: None,
        }
    }
}

/// The SMB2_PREAUTH_INTEGRITY_CAPABILITIES context is specified in an SMB2 NEGOTIATE
/// request by the client to indicate which preauthentication integrity hash algorithms
/// the client supports and to optionally supply a preauthentication integrity hash salt value.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PreauthIntegrityCapabilities {
    /// HashAlgorithmCount (2 bytes): The number of hash algorithms in
    /// the HashAlgorithms array. This value MUST be greater than zero.
    pub hash_algorithm_count: Vec<u8>,
    /// SaltLength (2 bytes): The size, in bytes, of the Salt field.
    pub salt_length: Vec<u8>,
    /// HashAlgorithms (variable): An array of HashAlgorithmCount
    /// 16-bit integer IDs specifying the supported preauthentication integrity hash functions.
    /// There is currently only SHA-512 available.
    pub hash_algorithms: Vec<Vec<u8>>,
    /// Salt (variable): A buffer containing the salt value of the hash.
    pub salt: Vec<u8>,
}

impl PreauthIntegrityCapabilities {
    /// Creates a new PreauthIntegrityCapabilities instance.
    pub fn default() -> Self {
        PreauthIntegrityCapabilities {
            hash_algorithm_count: b"\x01\x00".to_vec(),
            salt_length: Vec::new(),
            hash_algorithms: vec![b"\x01\x00".to_vec()], // SHA-512
            salt: Vec::new(),
        }
    }
}

/// An array of CipherCount 16-bit integer IDs specifying the supported encryption algorithms.
/// These IDs MUST be in an order such that the most preferred cipher MUST be at the beginning
/// of the array and least preferred cipher at the end of the array. The following IDs are defined.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Ciphers {
    Aes128Ccm,
    Aes128Gcm,
    Aes256Ccm,
    Aes256Gcm,
}

impl Ciphers {
    /// Unpacks the byte code of ciphers.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Ciphers::Aes128Ccm => b"\x01\x00".to_vec(),
            Ciphers::Aes128Gcm => b"\x02\x00".to_vec(),
            Ciphers::Aes256Ccm => b"\x03\x00".to_vec(),
            Ciphers::Aes256Gcm => b"\x04\x00".to_vec(),
        }
    }
}

/// The SMB2_ENCRYPTION_CAPABILITIES context is specified in an SMB2 NEGOTIATE
/// request by the client to indicate which encryption algorithms the client supports.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EncryptionCapabilities {
    /// CipherCount (2 bytes): The number of ciphers in the Ciphers array.
    /// This value MUST be greater than zero.
    pub cipher_count: Vec<u8>,
    /// Ciphers (variable): An array of CipherCount 16-bit integer IDs
    /// specifying the supported encryption algorithms.
    /// These IDs MUST be in an order such that the most preferred cipher
    /// MUST be at the beginning of the array and least preferred cipher
    /// at the end of the array.
    pub ciphers: Vec<Vec<u8>>,
}

impl EncryptionCapabilities {
    /// Creates a new EncryptionCapabilities instance.
    pub fn default() -> Self {
        EncryptionCapabilities {
            cipher_count: Vec::new(),
            ciphers: Vec::new(),
        }
    }
}

/// *Compression Capabilities Flag None*:
///     - Chained compression is not supported.
///
/// *Compression Capabilities Flag Chained*:
///     - Chained compression is supported on this connection.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Flags {
    CompressionCapabilitiesFlagNone,
    CompressionCapabilitiesFlagChained,
}

impl Flags {
    /// Unpacks the byte code for compression flags.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            Flags::CompressionCapabilitiesFlagNone => b"\x00\x00\x00\x00".to_vec(),
            Flags::CompressionCapabilitiesFlagChained => b"\x01\x00\x00\x00".to_vec(),
        }
    }
}

/// *None*:
///     - No compression.
///
/// *LZNT1*:
///     - LZNT1 compression algorithm.
///
/// *LZ77*:
///     - LZ77 compression algorithm.
///
/// *LZ77 + Huffman*:
///      - LZ77+Huffman compression algorithm.
///
/// *Pattern_V1*:
///     - Pattern scanning algorithm.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CompressionAlgorithms {
    None,
    Lznt1,
    Lz77,
    Lz77Huffman,
    PatternV1,
}

impl CompressionAlgorithms {
    /// Unpacks the byte code for compression algorithms.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            CompressionAlgorithms::None => b"\x00\x00".to_vec(),
            CompressionAlgorithms::Lznt1 => b"\x01\x00".to_vec(),
            CompressionAlgorithms::Lz77 => b"\x02\x00".to_vec(),
            CompressionAlgorithms::Lz77Huffman => b"\x03\x00".to_vec(),
            CompressionAlgorithms::PatternV1 => b"\x04\x00".to_vec(),
        }
    }
}

/// The SMB2_COMPRESSION_CAPABILITIES context is specified in an SMB2 NEGOTIATE request
/// by the client to indicate which compression algorithms the client supports.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CompressionCapabilities {
    /// CompressionAlgorithmCount (2 bytes): The number of elements in CompressionAlgorithms array.
    pub compression_algorithm_count: Vec<u8>,
    /// Padding (2 bytes): The sender MUST set this to 0, and the receiver MUST ignore it on receipt.
    pub padding: Vec<u8>,
    /// Flags (4 bytes)
    pub flags: Vec<u8>,
    /// CompressionAlgorithms (variable): An array of 16-bit integer IDs specifying
    /// the supported compression algorithms. These IDs MUST be in order of preference
    /// from most to least. The following IDs are defined.
    pub compression_algorithms: Vec<Vec<u8>>,
}

impl CompressionCapabilities {
    /// Creates a new compression capabilities instance.
    pub fn default() -> Self {
        CompressionCapabilities {
            compression_algorithm_count: Vec::new(),
            padding: b"\x00\x00".to_vec(),
            flags: Vec::new(),
            compression_algorithms: Vec::new(),
        }
    }
}

/// The SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context is specified in an SMB2 NEGOTIATE request
/// to indicate the server name the client connects to.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NetnameNegotiateContextId {
    /// NetName (variable): A Unicode string containing the server name and specified
    /// by the client application. e.g. 'tom'
    pub net_name: Vec<u8>,
}

impl NetnameNegotiateContextId {
    /// Creates a new NetnameNegotiateContextId instance.
    pub fn default() -> Self {
        NetnameNegotiateContextId {
            net_name: Vec::new(),
        }
    }
}

/// The SMB2_TRANSPORT_CAPABILITIES context is specified in an SMB2 NEGOTIATE request
/// to indicate transport capabilities over which the connection is made.
/// The server MUST ignore the context on receipt.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransportCapabilities {
    /// Reserved (4 bytes): This field SHOULD be set to zero and is ignored on receipt.
    pub reserved: Vec<u8>,
}

impl TransportCapabilities {
    /// Creates a new TransportCapabilities instance.
    pub fn default() -> Self {
        TransportCapabilities {
            reserved: b"\x00\x00\x00\x00".to_vec(),
        }
    }
}

/// *RDMA Transform None*:
///     - No transform
///
/// *RDMA Transform Encryption*:
///     - Encryption of data sent over RMDA.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RdmaTransformIds {
    RdmaTransformNone,
    RdmaTransformEncryption,
}

impl RdmaTransformIds {
    /// Unpacks the byte code of RDMA transform ids.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            RdmaTransformIds::RdmaTransformNone => b"\x00\x00".to_vec(),
            RdmaTransformIds::RdmaTransformEncryption => b"\x01\x00".to_vec(),
        }
    }
}

/// The RDMA_TRANSFORM_CAPABILITIES context is specified in an
/// SMB2 NEGOTIATE request by the client to indicate the transforms
/// supported when data is sent over RDMA.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RdmaTransformCapabilities {
    /// TransformCount (2 bytes): The number of elements in RDMATransformIds array.
    /// This value MUST be greater than 0.
    pub transform_count: Vec<u8>,
    /// Reserved1 (2 bytes): This field MUST NOT be used and MUST be reserved.
    /// The sender MUST set this to 0, and the receiver MUST ignore it on receipt.
    pub reserved1: Vec<u8>,
    /// Reserved2 (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// The sender MUST set this to 0, and the receiver MUST ignore it on receipt.
    pub reserved2: Vec<u8>,
    /// RDMATransformIds (variable): An array of 16-bit integer IDs specifying
    /// the supported RDMA transforms. The following IDs are defined.
    pub rdma_transform_ids: Vec<Vec<u8>>,
}

impl RdmaTransformCapabilities {
    /// Creates a new RDMATransformCapabilities instance.
    pub fn default() -> Self {
        RdmaTransformCapabilities {
            transform_count: Vec::new(),
            reserved1: b"\x00\x00".to_vec(),
            reserved2: b"\x00\x00\x00\x00".to_vec(),
            rdma_transform_ids: Vec::new(),
        }
    }
}
