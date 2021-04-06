//! The following SMB2 Access Mask flag values can be used when accessing a file, pipe or printer.

use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

/// File_Pipe_Printer_Access_Mask (4 bytes): For a file, pipe, or printer,
/// the value MUST be constructed using the following values (for a printer,
/// the value MUST have at least one of the following: FILE_WRITE_DATA,
/// FILE_APPEND_DATA, or GENERIC_WRITE).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FileAccessMask {
    ReadData,
    WriteData,
    AppendData,
    ReadEa,
    WriteEa,
    DeleteChild,
    Execute,
    ReadAttributes,
    WriteAttributes,
    Delete,
    ReadControl,
    WriteDac,
    WriteOwner,
    Synchronize,
    AccessSystemSecurity,
    MaximumAllowed,
    GenericAll,
    GenericExecute,
    GenericWrite,
    GenericRead,
}

impl FileAccessMask {
    /// Unpacks the byte code of the corresponding file access mask.
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            FileAccessMask::ReadData => 0x00000001,
            FileAccessMask::WriteData => 0x00000002,
            FileAccessMask::AppendData => 0x00000004,
            FileAccessMask::ReadEa => 0x00000008,
            FileAccessMask::WriteEa => 0x00000010,
            FileAccessMask::DeleteChild => 0x00000040,
            FileAccessMask::Execute => 0x00000020,
            FileAccessMask::ReadAttributes => 0x00000080,
            FileAccessMask::WriteAttributes => 0x00000100,
            FileAccessMask::Delete => 0x00010000,
            FileAccessMask::ReadControl => 0x00020000,
            FileAccessMask::WriteDac => 0x00040000,
            FileAccessMask::WriteOwner => 0x00080000,
            FileAccessMask::Synchronize => 0x00100000,
            FileAccessMask::AccessSystemSecurity => 0x01000000,
            FileAccessMask::MaximumAllowed => 0x02000000,
            FileAccessMask::GenericAll => 0x10000000,
            FileAccessMask::GenericExecute => 0x20000000,
            FileAccessMask::GenericWrite => 0x40000000,
            FileAccessMask::GenericRead => 0x80000000,
        }
    }

    /// Returns a sum of the given file access masks as a 4 byte array.
    pub fn return_sum_of_chosen_file_access_masks(file_access: Vec<FileAccessMask>) -> Vec<u8> {
        let combined_file_access_masks: u32 = file_access.iter().fold(0u32, |acc, access| {
            let temp: u64 = acc as u64 + access.unpack_byte_code() as u64;
            if temp < u32::MAX as u64 {
                acc + access.unpack_byte_code()
            } else {
                acc
            }
        });

        combined_file_access_masks.to_le_bytes().to_vec()
    }
}

impl Distribution<FileAccessMask> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> FileAccessMask {
        match rng.gen_range(0..=19) {
            0 => FileAccessMask::ReadData,
            1 => FileAccessMask::WriteData,
            2 => FileAccessMask::AppendData,
            3 => FileAccessMask::ReadEa,
            4 => FileAccessMask::WriteEa,
            5 => FileAccessMask::DeleteChild,
            6 => FileAccessMask::Execute,
            7 => FileAccessMask::ReadAttributes,
            8 => FileAccessMask::WriteAttributes,
            9 => FileAccessMask::Delete,
            10 => FileAccessMask::ReadControl,
            11 => FileAccessMask::WriteDac,
            12 => FileAccessMask::WriteOwner,
            13 => FileAccessMask::Synchronize,
            14 => FileAccessMask::AccessSystemSecurity,
            15 => FileAccessMask::MaximumAllowed,
            16 => FileAccessMask::GenericAll,
            17 => FileAccessMask::GenericExecute,
            18 => FileAccessMask::GenericWrite,
            _ => FileAccessMask::GenericRead,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_return_sum_of_chosen_file_access_masks() {
        assert_eq!(
            b"\x89\x00\x12\x00".to_vec(),
            FileAccessMask::return_sum_of_chosen_file_access_masks(vec![
                FileAccessMask::ReadData,
                FileAccessMask::ReadEa,
                FileAccessMask::ReadAttributes,
                FileAccessMask::ReadControl,
                FileAccessMask::Synchronize,
            ])
        );
    }
}
