/// Echo request size of 4 bytes
const STRUCTURE_SIZE: &[u8; 2] = b"\x04\x00";

/// The SMB2 ECHO Request packet is sent by a client to determine whether a server is
/// processing requests. This request is composed of an SMB2 header, followed by this request structure:
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Echo {
    /// StructureSize (2 bytes): The client MUST set this to 4,
    /// indicating the size of the request structure, not including the header.
    pub structure_size: Vec<u8>,
    /// Reserved (2 bytes): This field MUST NOT be used and MUST be reserved.
    /// The client MUST set this to 0, and the server MUST ignore it on receipt.
    pub reserved: Vec<u8>,
}

impl Echo {
    /// Creates a new default instance of the Echo request.
    pub fn default() -> Self {
        Echo {
            structure_size: STRUCTURE_SIZE.to_vec(),
            reserved: vec![0; 2],
        }
    }

    /// Creates a new fuzzed instance of the Echo request.
    pub fn fuzzed(structure_size: Vec<u8>, reserved: Vec<u8>) -> Self {
        Echo {
            structure_size,
            reserved,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_default() {
        let echo_request = Echo::default();

        assert_eq!(vec![4, 0], echo_request.structure_size);
        assert_eq!(vec![0, 0], echo_request.reserved);
    }

    #[test]
    fn test_echo_fuzzed() {
        let echo_request = Echo::fuzzed(b"\x01\x02\x03".to_vec(), b"\x01\x02\x03".to_vec());

        assert_eq!(vec![1, 2, 3], echo_request.structure_size);
        assert_eq!(vec![1, 2, 3], echo_request.reserved);
    }
}
