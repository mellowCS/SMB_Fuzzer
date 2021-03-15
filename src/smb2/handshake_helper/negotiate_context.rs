//! This module describes the negotiate contexts.

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContextType {
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities),
    EncryptionCapabilities(EncryptionCapabilities),
    CompressionCapabilities(CompressionCapabilities),
    NetnameNegotiateContextId(NetnameNegotiateContextId),
    TransportCapabilities(TransportCapabilities),
    RDMATransformCapabilities(RDMATransformCapabilities),
}

impl ContextType {
    /// Unpacks the byte code for the context type.
    pub fn unpack_byte_code(&self) -> String {
        match self {
            ContextType::PreauthIntegrityCapabilities(_) => String::from("0001"),
            ContextType::EncryptionCapabilities(_) => String::from("0002"),
            ContextType::CompressionCapabilities(_) => String::from("0003"),
            ContextType::NetnameNegotiateContextId(_) => String::from("0005"),
            ContextType::TransportCapabilities(_) => String::from("0006"),
            ContextType::RDMATransformCapabilities(_) => String::from("0007"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NegotiateContext {
    /// ContextType (2 bytes): Specifies the type of context in the Data field.
    context_type: String,
    /// DataLength (2 bytes): The length, in bytes, of the Data field.
    data_length: String,
    /// Reserved (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// This value MUST be set to 0 by the client, and MUST be ignored by the server.
    reserved: String,
    /// Data (variable): A variable-length field that contains
    /// the negotiate context specified by the ContextType field.
    data: ContextType,
}

/// The SMB2_PREAUTH_INTEGRITY_CAPABILITIES context is specified in an SMB2 NEGOTIATE
/// request by the client to indicate which preauthentication integrity hash algorithms
/// the client supports and to optionally supply a preauthentication integrity hash salt value.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PreauthIntegrityCapabilities {
    /// HashAlgorithmCount (2 bytes): The number of hash algorithms in
    /// the HashAlgorithms array. This value MUST be greater than zero.
    hash_algorithm_count: String,
    /// SaltLength (2 bytes): The size, in bytes, of the Salt field.
    salt_length: String,
    /// HashAlgorithms (variable): An array of HashAlgorithmCount
    /// 16-bit integer IDs specifying the supported preauthentication integrity hash functions.
    /// There is currently only SHA-512 available.
    hash_algorithms: Vec<String>,
    /// Salt (variable): A buffer containing the salt value of the hash.
    salt: String,
}

impl PreauthIntegrityCapabilities {
    /// Creates a new PreauthIntegrityCapabilities instance.
    pub fn default() -> Self {
        PreauthIntegrityCapabilities {
            hash_algorithm_count: String::from("0001"),
            salt_length: String::new(),
            hash_algorithms: vec![String::from("0001")], // SHA-512
            salt: String::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Ciphers {
    AES128CCM,
    AES128GCM,
    AES256CCM,
    AES256GCM,
}

impl Ciphers {
    /// Unpacks the byte code of ciphers.
    pub fn unpack_byte_code(&self) -> String {
        match self {
            Ciphers::AES128CCM => String::from("0001"),
            Ciphers::AES128GCM => String::from("0002"),
            Ciphers::AES256CCM => String::from("0003"),
            Ciphers::AES256GCM => String::from("0004"),
        }
    }
}

/// The SMB2_ENCRYPTION_CAPABILITIES context is specified in an SMB2 NEGOTIATE
/// request by the client to indicate which encryption algorithms the client supports.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EncryptionCapabilities {
    /// CipherCount (2 bytes): The number of ciphers in the Ciphers array.
    /// This value MUST be greater than zero.
    cipher_count: String,
    /// Ciphers (variable): An array of CipherCount 16-bit integer IDs
    /// specifying the supported encryption algorithms.
    /// These IDs MUST be in an order such that the most preferred cipher
    /// MUST be at the beginning of the array and least preferred cipher
    /// at the end of the array.
    ciphers: Vec<String>,
}

impl EncryptionCapabilities {
    /// Creates a new EncryptionCapabilities instance.
    pub fn default() -> Self {
        EncryptionCapabilities {
            cipher_count: String::new(),
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
    pub fn unpack_byte_code(&self) -> String {
        match self {
            Flags::CompressionCapabilitiesFlagNone => String::from("00000000"),
            Flags::CompressionCapabilitiesFlagChained => String::from("00000001"),
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
    LZNT1,
    LZ77,
    LZ77Huffman,
    PatternV1,
}

impl CompressionAlgorithms {
    /// Unpacks the byte code for compression algorithms.
    pub fn unpack_byte_code(&self) -> String {
        match self {
            CompressionAlgorithms::None => String::from("0000"),
            CompressionAlgorithms::LZNT1 => String::from("0001"),
            CompressionAlgorithms::LZ77 => String::from("0002"),
            CompressionAlgorithms::LZ77Huffman => String::from("0003"),
            CompressionAlgorithms::PatternV1 => String::from("0004"),
        }
    }
}

/// The SMB2_COMPRESSION_CAPABILITIES context is specified in an SMB2 NEGOTIATE request
/// by the client to indicate which compression algorithms the client supports.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CompressionCapabilities {
    /// CompressionAlgorithmCount (2 bytes): The number of elements in CompressionAlgorithms array.
    compression_algorithm_count: String,
    /// Padding (2 bytes): The sender MUST set this to 0, and the receiver MUST ignore it on receipt.
    padding: String,
    /// Flags (4 bytes)
    flags: Vec<String>,
    /// CompressionAlgorithms (variable): An array of 16-bit integer IDs specifying
    /// the supported compression algorithms. These IDs MUST be in order of preference
    /// from most to least. The following IDs are defined.
    compression_algorithms: Vec<String>,
}

impl CompressionCapabilities {
    /// Creates a new compression capabilities instance.
    pub fn default() -> Self {
        CompressionCapabilities {
            compression_algorithm_count: String::new(),
            padding: String::from("0000"),
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
    net_name: String,
}

impl NetnameNegotiateContextId {
    /// Creates a new NetnameNegotiateContextId instance.
    pub fn default() -> Self {
        NetnameNegotiateContextId {
            net_name: String::new(),
        }
    }
}

/// The SMB2_TRANSPORT_CAPABILITIES context is specified in an SMB2 NEGOTIATE request
/// to indicate transport capabilities over which the connection is made.
/// The server MUST ignore the context on receipt.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransportCapabilities {
    /// Reserved (4 bytes): This field SHOULD be set to zero and is ignored on receipt.
    reserved: String,
}

impl TransportCapabilities {
    /// Creates a new TransportCapabilities instance.
    pub fn default() -> Self {
        TransportCapabilities {
            reserved: String::from("00000000"),
        }
    }
}

/// *RDMA Transform None*:
///     - No transform
///
/// *RDMA Transform Encryption*:
///     - Encryption of data sent over RMDA.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RDMATransformIds {
    RDMATransformNone,
    RDMATransformEncryption,
}

impl RDMATransformIds {
    /// Unpacks the byte code of RDMA transform ids.
    pub fn unpack_byte_code(&self) -> String {
        match self {
            RDMATransformIds::RDMATransformNone => String::from("0000"),
            RDMATransformIds::RDMATransformEncryption => String::from("0001"),
        }
    }
}

/// The RDMA_TRANSFORM_CAPABILITIES context is specified in an
/// SMB2 NEGOTIATE request by the client to indicate the transforms
/// supported when data is sent over RDMA.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RDMATransformCapabilities {
    /// TransformCount (2 bytes): The number of elements in RDMATransformIds array.
    /// This value MUST be greater than 0.
    transform_count: String,
    /// Reserved1 (2 bytes): This field MUST NOT be used and MUST be reserved.
    /// The sender MUST set this to 0, and the receiver MUST ignore it on receipt.
    reserved1: String,
    /// Reserved2 (4 bytes): This field MUST NOT be used and MUST be reserved.
    /// The sender MUST set this to 0, and the receiver MUST ignore it on receipt.
    reserved2: String,
    /// RDMATransformIds (variable): An array of 16-bit integer IDs specifying
    /// the supported RDMA transforms. The following IDs are defined.
    rdma_transform_ids: Vec<String>,
}

impl RDMATransformCapabilities {
    /// Creates a new RDMATransformCapabilities instance.
    pub fn default() -> Self {
        RDMATransformCapabilities {
            transform_count: String::new(),
            reserved1: String::from("0000"),
            reserved2: String::from("0000"),
            rdma_transform_ids: Vec::new(),
        }
    }
}
