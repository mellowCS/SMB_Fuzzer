/// *Negotiate Signing Enabled*:
///     - When set, indicates that security signatures are enabled on the client.
///       The client MUST set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is not set,
///       and MUST NOT set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set.
///       The server MUST ignore this bit.
///
/// *Negotiate Signing Required*:
///     - When set, indicates that security signatures are required by the client.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SecurityMode {
    NegotiateSigningEnabled,
    NegotiateSigningRequired,
}

impl SecurityMode {
    /// TODO: Modes can be combined. Add function for adding hex numbers and don't forget that security mode is avaiable
    /// as a 1 byte and 2 byte version.
    /// Return the corresponding byte code (byte_size bytes) for each security mode.
    pub fn unpack_byte_code(&self, byte_size: u32) -> Vec<u8> {
        let prefix = "00".repeat(byte_size as usize - 1);
        match self {
            SecurityMode::NegotiateSigningEnabled => {
                hex::decode(prefix + "01").expect("Could not decode hex string to raw bytes.")
            }
            SecurityMode::NegotiateSigningRequired => {
                hex::decode(prefix + "02").expect("Could not decode hex string to raw bytes.")
            }
        }
    }
}

/// *Global Cap DFS*:
///     - When set, indicates that the client supports the Distributed File System (DFS).
///
/// *Global Cap Leasing*:
///     - When set, indicates that the client supports leasing.
///
/// *Global Cap Large MTU*:
///     - When set, indicates that the client supports multi-credit operations.
///
/// *Global Cap Multi Channel*:
///     - When set, indicates that the client supports establishing multiple channels for a single session.
///
/// *Global Cap Persistent Handles*:
///     - When set, indicates that the client supports persistent handles.
///
/// *Global Cap Directory Leasing*:
///     - When set, indicates that the client supports directory leasing.
///
/// *Global Cap Encryption*:
///     - When set, indicates that the client supports encryption.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Capabilities {
    GlobalCapDFS,
    GlobalCapLeasing,
    GlobalCapLargeMTU,
    GlobalCapMultiChannel,
    GlobalCapPersistentHandles,
    GlobalCapDirectoryLeasing,
    GlobalCapEncryption,
    Zero,
}

impl Capabilities {
    /// Return the corresponding byte code (4 bytes) for each capability.
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            Capabilities::GlobalCapDFS => 0x00000001,
            Capabilities::GlobalCapLeasing => 0x00000002,
            Capabilities::GlobalCapLargeMTU => 0x00000004,
            Capabilities::GlobalCapMultiChannel => 0x00000008,
            Capabilities::GlobalCapPersistentHandles => 0x00000010,
            Capabilities::GlobalCapDirectoryLeasing => 0x00000020,
            Capabilities::GlobalCapEncryption => 0x00000040,
            Capabilities::Zero => 0x00000000,
        }
    }

    /// Add all capabilities values together and return them as a hex string.
    pub fn return_all_capabilities() -> Vec<u8> {
        let combined_capabilities = Self::GlobalCapDFS.unpack_byte_code()
            + Self::GlobalCapLeasing.unpack_byte_code()
            + Self::GlobalCapLargeMTU.unpack_byte_code()
            + Self::GlobalCapMultiChannel.unpack_byte_code()
            + Self::GlobalCapPersistentHandles.unpack_byte_code()
            + Self::GlobalCapDirectoryLeasing.unpack_byte_code()
            + Self::GlobalCapEncryption.unpack_byte_code();

        hex::decode(
            format!("{:#10x}", combined_capabilities)
                .strip_prefix("0x")
                .unwrap()
                .to_string(),
        )
        .expect("Could not decode capabilities hex string to raw bytes.")
    }
}
