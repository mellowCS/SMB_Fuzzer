//! This module represents the logoff request and response.
//! The SMB2 LOGOFF Request packet is sent by the client to request termination of a particular session.
//! This request is composed of an SMB2 header, followed by this request structure.
//! The SMB2 LOGOFF Response packet is sent by the server to confirm that an SMB2 LOGOFF Request was completed successfully.
//! This response is composed of an SMB2 header, followed by this request structure.

/// logoff request size of 4 bytes
const STRUCTURE_SIZE: &str = "0400";

/// A struct that represents a logoff request and response.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LogOff {
    /// StructureSize (2 bytes): The client/server MUST set this field to 4,
    /// indicating the size of the request structure not including the header.
    structure_size: String,
    /// Reserved (2 bytes): This field MUST NOT be used and MUST be reserved.
    /// The client/server MUST set this to 0, and the server/client MUST ignore it on receipt.
    reserved: String,
}

impl LogOff {
    /// Creates a new Logoff instance.
    pub fn default() -> Self {
        LogOff {
            structure_size: String::from(STRUCTURE_SIZE),
            reserved: String::from("0000"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::LogOff;

    #[test]
    fn new_logoff() {
        let logoff = LogOff::default();
        assert_eq!(logoff.structure_size, String::from("0400"));
        assert_eq!(logoff.reserved, String::from("0000"))
    }
}
