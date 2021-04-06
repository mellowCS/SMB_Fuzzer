use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
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
        let mut prefix: Vec<u8> = vec![0; (byte_size - 1) as usize];
        match self {
            SecurityMode::NegotiateSigningEnabled => {
                prefix.insert(0, 1);
                prefix
            }
            SecurityMode::NegotiateSigningRequired => {
                prefix.insert(0, 2);
                prefix
            }
        }
    }

    /// Maps the byte code of an incoming response to the corresponding security mode.
    pub fn map_byte_code_to_mode(byte_code: Vec<u8>) -> SecurityMode {
        if let Some(code) = byte_code.get(0) {
            match code {
                1 => SecurityMode::NegotiateSigningEnabled,
                2 => SecurityMode::NegotiateSigningRequired,
                _ => panic!("Invalid security mode."),
            }
        } else {
            panic!("Empty byte code for security mode.");
        }
    }
}

impl Distribution<SecurityMode> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecurityMode {
        match rng.gen_range(0..=1) {
            0 => SecurityMode::NegotiateSigningEnabled,
            _ => SecurityMode::NegotiateSigningRequired,
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
    GlobalCapDfs,
    GlobalCapLeasing,
    GlobalCapLargeMtu,
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
            Capabilities::GlobalCapDfs => 0x00000001,
            Capabilities::GlobalCapLeasing => 0x00000002,
            Capabilities::GlobalCapLargeMtu => 0x00000004,
            Capabilities::GlobalCapMultiChannel => 0x00000008,
            Capabilities::GlobalCapPersistentHandles => 0x00000010,
            Capabilities::GlobalCapDirectoryLeasing => 0x00000020,
            Capabilities::GlobalCapEncryption => 0x00000040,
            Capabilities::Zero => 0x00000000,
        }
    }

    /// Add the values of a list of chosen capabilities and return the sum as a hex string.
    pub fn return_sum_of_chosen_capabilities(capabilities: Vec<Capabilities>) -> Vec<u8> {
        let combined_cap: u32 = capabilities
            .iter()
            .fold(0, |acc, cap| acc + cap.unpack_byte_code());

        combined_cap.to_le_bytes().to_vec()
    }

    /// Shortcut for returning all capabilities as a sum.
    pub fn return_all_capabilities() -> Vec<u8> {
        Capabilities::return_sum_of_chosen_capabilities(vec![
            Capabilities::GlobalCapDfs,
            Capabilities::GlobalCapLeasing,
            Capabilities::GlobalCapLargeMtu,
            Capabilities::GlobalCapMultiChannel,
            Capabilities::GlobalCapPersistentHandles,
            Capabilities::GlobalCapDirectoryLeasing,
            Capabilities::GlobalCapEncryption,
        ])
    }
}

impl Distribution<Capabilities> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Capabilities {
        match rng.gen_range(0..=6) {
            0 => Capabilities::GlobalCapDfs,
            1 => Capabilities::GlobalCapLeasing,
            2 => Capabilities::GlobalCapLargeMtu,
            3 => Capabilities::GlobalCapMultiChannel,
            4 => Capabilities::GlobalCapPersistentHandles,
            5 => Capabilities::GlobalCapDirectoryLeasing,
            _ => Capabilities::GlobalCapEncryption,
        }
    }
}

/// OplockLevel (1 byte): The oplock level.
/// This field MUST contain one of the following values.
/// For named pipes, the server MUST always revert to SMB2_OPLOCK_LEVEL_NONE
/// irrespective of the value of this field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OplockLevel {
    None,
    Level2,
    Exclusive,
    Batch,
    Lease,
}

impl OplockLevel {
    /// Unpacks the byte code of the corresponding requested oplock level.
    pub fn unpack_byte_code(&self) -> Vec<u8> {
        match self {
            OplockLevel::None => b"\x00".to_vec(),
            OplockLevel::Level2 => b"\x01".to_vec(),
            OplockLevel::Exclusive => b"\x08".to_vec(),
            OplockLevel::Batch => b"\x09".to_vec(),
            OplockLevel::Lease => b"\xff".to_vec(),
        }
    }
}

impl Distribution<OplockLevel> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> OplockLevel {
        match rng.gen_range(0..=4) {
            0 => OplockLevel::None,
            1 => OplockLevel::Level2,
            2 => OplockLevel::Exclusive,
            3 => OplockLevel::Batch,
            _ => OplockLevel::Lease,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_return_sum_of_chosen_capabilities() {
        let chosen = vec![
            Capabilities::GlobalCapDfs,
            Capabilities::GlobalCapLeasing,
            Capabilities::GlobalCapLargeMtu,
            Capabilities::GlobalCapMultiChannel,
            Capabilities::GlobalCapPersistentHandles,
            Capabilities::GlobalCapDirectoryLeasing,
            Capabilities::GlobalCapEncryption,
        ];

        assert_eq!(
            vec![127, 0, 0, 0],
            Capabilities::return_sum_of_chosen_capabilities(chosen)
        );
    }
}
