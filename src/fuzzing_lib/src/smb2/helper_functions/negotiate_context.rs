//! This module describes the negotiate contexts.
//! The SMB2_NEGOTIATE_CONTEXT structure is used by the SMB2 NEGOTIATE Request
//! and the SMB2 NEGOTIATE Response to encode additional properties.
//! The server MUST support receiving negotiate contexts in any order.

use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

use crate::{
    format::convert_byte_array_to_int, fuzzer::create_random_byte_array_of_predefined_length,
};

pub trait DataSize {
    fn get_data_length(&self) -> Vec<u8>;
}

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

    /// Calls get data length for the corresponding capability.
    pub fn get_capability_data_length(&self) -> Vec<u8> {
        match self {
            ContextType::PreauthIntegrityCapabilities(preauth) => preauth.get_data_length(),
            ContextType::EncryptionCapabilities(encrypt) => encrypt.get_data_length(),
            ContextType::CompressionCapabilities(compress) => compress.get_data_length(),
            ContextType::NetnameNegotiateContextId(netname) => netname.get_data_length(),
            ContextType::TransportCapabilities(transport) => transport.get_data_length(),
            ContextType::RdmaTransformCapabilities(rdma) => rdma.get_data_length(),
        }
    }
}

impl Distribution<ContextType> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ContextType {
        match rng.gen_range(0..=4) {
            0 => ContextType::PreauthIntegrityCapabilities(
                PreauthIntegrityCapabilities::fuzz_with_predefined_length(),
            ),
            1 => ContextType::EncryptionCapabilities(
                EncryptionCapabilities::fuzz_with_predefined_length(),
            ),
            2 => ContextType::CompressionCapabilities(
                CompressionCapabilities::fuzz_with_predefined_length(),
            ),
            3 => ContextType::NetnameNegotiateContextId(NetnameNegotiateContextId::fuzz()),
            4 => ContextType::TransportCapabilities(
                TransportCapabilities::fuzz_with_predefined_length(),
            ),
            _ => ContextType::RdmaTransformCapabilities(
                RdmaTransformCapabilities::fuzz_with_predefined_length(),
            ),
        }
    }
}

impl std::fmt::Display for ContextType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ContextType::PreauthIntegrityCapabilities(preauth) => {
                write!(f, "{}", preauth)
            }
            ContextType::EncryptionCapabilities(encrypt) => {
                write!(f, "{}", encrypt)
            }
            ContextType::CompressionCapabilities(compress) => {
                write!(f, "{}", compress)
            }
            ContextType::NetnameNegotiateContextId(netname) => {
                write!(f, "{}", netname)
            }
            ContextType::TransportCapabilities(transport) => {
                write!(f, "{}", transport)
            }
            ContextType::RdmaTransformCapabilities(rdma) => {
                write!(f, "{}", rdma)
            }
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

impl std::fmt::Display for NegotiateContext {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Negotiate Context: \n\t\tcontext type: {:?}\n\t\tdata length: {:?}\
                   \n\t\treserved: {:?}\n\t\tdata: {}",
            self.context_type,
            self.data_length,
            self.reserved,
            self.data.as_ref().unwrap()
        )
    }
}

pub struct NegVec<'a>(pub &'a Vec<NegotiateContext>);

impl<'a> std::fmt::Display for NegVec<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut context_string = String::new();
        for context in self.0.iter() {
            context_string.push_str(format!("{}\n", context).as_str());
        }
        write!(f, "{}", context_string)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HashAlgorithms {
    Sha512,
}

impl HashAlgorithms {
    /// Unpacks the byte code for hash algorithms.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            HashAlgorithms::Sha512 => b"\x01\x00".to_vec(),
        }
    }
}

impl Distribution<HashAlgorithms> for Standard {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> HashAlgorithms {
        HashAlgorithms::Sha512
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

    /// Fuzzes the preauthintegrity capabilities with a predefined length.
    pub fn fuzz_with_predefined_length() -> Self {
        let mut random_hashes: Vec<HashAlgorithms> = Vec::new();
        for _ in 0..rand::thread_rng().gen_range(0..100) {
            random_hashes.push(rand::random());
        }
        let salt_length = rand::thread_rng().gen_range(0..32) as u16;
        PreauthIntegrityCapabilities {
            hash_algorithm_count: (random_hashes.len() as u16).to_le_bytes().to_vec(),
            salt_length: salt_length.to_le_bytes().to_vec(),
            hash_algorithms: random_hashes
                .into_iter()
                .map(|hash| hash.unpack_byte_code())
                .collect(),
            salt: create_random_byte_array_of_predefined_length(salt_length as u32),
        }
    }
}

impl DataSize for PreauthIntegrityCapabilities {
    /// Gets the data length of the preauthintegrity capabilities.
    fn get_data_length(&self) -> Vec<u8> {
        let length = self.hash_algorithm_count.len()
            + self.salt_length.len()
            + convert_byte_array_to_int(self.hash_algorithm_count.clone(), false) as usize
            + self.salt.len();

        (length as u16).to_le_bytes().to_vec()
    }
}

impl std::fmt::Display for PreauthIntegrityCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\n\t\t\tPreauth Integrity Capabilities: \n\t\t\t\thash algorithm count: {:?}\
                   \n\t\t\t\tsalt length: {:?}\n\t\t\t\thash algorithms: {:?}\n\t\t\t\tsalt: {:?}",
            self.hash_algorithm_count, self.salt_length, self.hash_algorithms, self.salt
        )
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

impl Distribution<Ciphers> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Ciphers {
        match rng.gen_range(0..=3) {
            0 => Ciphers::Aes128Ccm,
            1 => Ciphers::Aes128Gcm,
            2 => Ciphers::Aes256Ccm,
            _ => Ciphers::Aes256Gcm,
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

    /// Fuzzes the encryption capabilities with the predefined length.
    pub fn fuzz_with_predefined_length() -> Self {
        let mut random_ciphers: Vec<Ciphers> = Vec::new();
        for _ in 0..rand::thread_rng().gen_range(0..100) {
            random_ciphers.push(rand::random());
        }
        EncryptionCapabilities {
            cipher_count: (random_ciphers.len() as u16).to_le_bytes().to_vec(),
            ciphers: random_ciphers
                .into_iter()
                .map(|cipher| cipher.unpack_byte_code())
                .collect(),
        }
    }

    /// Gets the data length of the encrytpion capabilities.
    pub fn get_data_length(&self) -> Vec<u8> {
        let length = self.cipher_count.len()
            + convert_byte_array_to_int(self.cipher_count.clone(), false) as usize;

        (length as u16).to_le_bytes().to_vec()
    }
}

impl DataSize for EncryptionCapabilities {
    /// Gets the data length of the encrytpion capabilities.
    fn get_data_length(&self) -> Vec<u8> {
        let length = self.cipher_count.len()
            + convert_byte_array_to_int(self.cipher_count.clone(), false) as usize;

        (length as u16).to_le_bytes().to_vec()
    }
}

impl std::fmt::Display for EncryptionCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\n\t\t\tEncryption Capabilities: \n\t\t\t\tcipher count: {:?}\n\t\t\t\tciphers: {:?}",
            self.cipher_count, self.ciphers
        )
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

impl Distribution<Flags> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Flags {
        match rng.gen_range(0..=1) {
            0 => Flags::CompressionCapabilitiesFlagNone,
            _ => Flags::CompressionCapabilitiesFlagChained,
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

impl Distribution<CompressionAlgorithms> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CompressionAlgorithms {
        match rng.gen_range(0..=4) {
            0 => CompressionAlgorithms::None,
            1 => CompressionAlgorithms::Lznt1,
            2 => CompressionAlgorithms::Lz77,
            3 => CompressionAlgorithms::Lz77Huffman,
            _ => CompressionAlgorithms::PatternV1,
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

    /// Fuzzes the compression capabilities with the predefined length.
    pub fn fuzz_with_predefined_length() -> Self {
        let mut random_algorithms: Vec<CompressionAlgorithms> = Vec::new();
        for _ in 0..rand::thread_rng().gen_range(0..100) {
            random_algorithms.push(rand::random());
        }
        CompressionCapabilities {
            compression_algorithm_count: (random_algorithms.len() as u16).to_le_bytes().to_vec(),
            padding: b"\x00\x00".to_vec(),
            flags: rand::random::<Flags>().unpack_byte_code(),
            compression_algorithms: random_algorithms
                .into_iter()
                .map(|algo| algo.unpack_byte_code())
                .collect(),
        }
    }
}

impl DataSize for CompressionCapabilities {
    /// Gets the data size of the compression capabilities.
    fn get_data_length(&self) -> Vec<u8> {
        let length = self.compression_algorithm_count.len()
            + self.padding.len()
            + self.flags.len()
            + convert_byte_array_to_int(self.compression_algorithm_count.clone(), false) as usize;

        (length as u16).to_le_bytes().to_vec()
    }
}

impl std::fmt::Display for CompressionCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\n\t\t\tCompression Capabilities: \n\t\t\t\talgorithm count: {:?}\
                   \n\t\t\t\tpadding: {:?}\n\t\t\t\tflags: {:?}\n\t\t\t\talgorithms: {:?}",
            self.compression_algorithm_count, self.padding, self.flags, self.compression_algorithms
        )
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

    /// Fuzzess the netname with random bytes and a random length up to 100 bytes.
    pub fn fuzz() -> Self {
        NetnameNegotiateContextId {
            net_name: create_random_byte_array_of_predefined_length(
                rand::thread_rng().gen_range(0..100),
            ),
        }
    }
}

impl DataSize for NetnameNegotiateContextId {
    /// Gets the data size of the netname context id.
    fn get_data_length(&self) -> Vec<u8> {
        (self.net_name.len() as u16).to_le_bytes().to_vec()
    }
}

impl std::fmt::Display for NetnameNegotiateContextId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\n\t\t\tNetname Context ID: \n\t\t\t\tnetname: {:?}",
            self.net_name
        )
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

    /// Fuzzes the transport capabilities with the predefined length.
    pub fn fuzz_with_predefined_length() -> Self {
        TransportCapabilities {
            reserved: create_random_byte_array_of_predefined_length(4),
        }
    }

    /// Fuzzes the transport capabilities with random length and bytes.
    pub fn fuzz_with_random_length() -> Self {
        TransportCapabilities {
            reserved: create_random_byte_array_of_predefined_length(
                rand::thread_rng().gen_range(0..100),
            ),
        }
    }
}

impl DataSize for TransportCapabilities {
    /// Gets the data length of the transport capabilities.
    fn get_data_length(&self) -> Vec<u8> {
        (self.reserved.len() as u16).to_le_bytes().to_vec()
    }
}

impl std::fmt::Display for TransportCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\n\t\t\tTransport Capabilities: \n\t\t\t\treserved: {:?}",
            self.reserved
        )
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

impl Distribution<RdmaTransformIds> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RdmaTransformIds {
        match rng.gen_range(0..=1) {
            0 => RdmaTransformIds::RdmaTransformNone,
            _ => RdmaTransformIds::RdmaTransformEncryption,
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

    /// Fuzzes the rdma transform capabilities with the predefined length.
    /// and semi-valid values.
    pub fn fuzz_with_predefined_length() -> Self {
        let mut random_ids: Vec<RdmaTransformIds> = Vec::new();
        for _ in 0..rand::thread_rng().gen_range(0..100) {
            random_ids.push(rand::random());
        }

        RdmaTransformCapabilities {
            transform_count: (random_ids.len() as u16).to_le_bytes().to_vec(),
            reserved1: b"\x00\x00".to_vec(),
            reserved2: b"\x00\x00\x00\x00".to_vec(),
            rdma_transform_ids: random_ids
                .into_iter()
                .map(|id| id.unpack_byte_code())
                .collect(),
        }
    }
}

impl DataSize for RdmaTransformCapabilities {
    /// Gets the data length of the rdma transform capabilities.
    fn get_data_length(&self) -> Vec<u8> {
        let length = self.transform_count.len()
            + self.reserved1.len()
            + self.reserved2.len()
            + convert_byte_array_to_int(self.transform_count.clone(), false) as usize;

        (length as u16).to_le_bytes().to_vec()
    }
}

impl std::fmt::Display for RdmaTransformCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\n\t\t\tRDMA Transform Capabilities: \n\t\t\t\ttransform count: {:?}\
                   \n\t\t\t\treserved1: {:?}\n\t\t\t\treserved2: {:?}\n\t\t\t\tids: {:?}",
            self.transform_count, self.reserved1, self.reserved2, self.rdma_transform_ids
        )
    }
}
