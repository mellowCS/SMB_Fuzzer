/// The following attributes are defined for files and directories.
/// They can be used in any combination unless noted in the description of the attribute's meaning.
/// There is no file attribute with the value 0x00000000 because a value of 0x00000000 in the
/// FileAttributes field means that the file attributes for this file MUST NOT be changed
/// when setting basic information for the file.
///
/// Note: File systems silently ignore any attribute that is not supported by that file system.  
/// Unsupported attributes MUST NOT be persisted on the media. It is recommended that unsupported
/// attributes be masked off when encountered.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FileAttributes {
    Archive,
    Compressed,
    Directory,
    Encrypted,
    Hidden,
    Normal,
    NotContentIndexed,
    Offline,
    Readonly,
    ReparsePoint,
    SparseFile,
    System,
    Temporary,
    IntegrityStream,
    NoScrubData,
}

impl FileAttributes {
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            FileAttributes::Archive => 0x00000020,
            FileAttributes::Compressed => 0x00000800,
            FileAttributes::Directory => 0x00000010,
            FileAttributes::Encrypted => 0x00004000,
            FileAttributes::Hidden => 0x00000002,
            FileAttributes::Normal => 0x00000080,
            FileAttributes::NotContentIndexed => 0x00002000,
            FileAttributes::Offline => 0x00001000,
            FileAttributes::Readonly => 0x00000001,
            FileAttributes::ReparsePoint => 0x00000400,
            FileAttributes::SparseFile => 0x00000200,
            FileAttributes::System => 0x00000004,
            FileAttributes::Temporary => 0x00000100,
            FileAttributes::IntegrityStream => 0x00008000,
            FileAttributes::NoScrubData => 0x00020000,
        }
    }

    /// Returns a sum of the given file attributes as a 4 byte array.
    pub fn return_sum_of_chosen_file_attributes(attr: Vec<FileAttributes>) -> Vec<u8> {
        let combined_attr: u32 = attr
            .iter()
            .fold(0u32, |acc, attribute| acc + attribute.unpack_byte_code());

        combined_attr.to_le_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_return_sum_of_chosen_file_attributes() {
        let attr = vec![
            FileAttributes::Archive,
            FileAttributes::IntegrityStream,
            FileAttributes::Encrypted,
        ];

        assert_eq!(
            vec![32, 192, 0, 0],
            FileAttributes::return_sum_of_chosen_file_attributes(attr)
        );
    }
}
