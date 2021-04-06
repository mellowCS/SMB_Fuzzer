use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CreateOptions {
    DirectoryFile,
    WriteThrough,
    SequentialOnly,
    NoIntermediateBuffering,
    SynchronousIoAlert,
    SynchronousIoNonAlert,
    NonDirectoryFile,
    CompleteIfOplocked,
    NoEaKnowledge,
    RandomAccess,
    DeleteOnClose,
    OpenByFileId,
    OpenForBackupIntent,
    NoCompression,
    OpenRemoteInstance,
    OpenRequiringOplock,
    DisallowExclusive,
    ReserveOpfilter,
    OpenReparsePoint,
    OpenNoRecall,
    OpenForFreeSpaceQuery,
}

impl CreateOptions {
    pub fn unpack_byte_code(&self) -> u32 {
        match self {
            CreateOptions::DirectoryFile => 0x00000001,
            CreateOptions::WriteThrough => 0x00000002,
            CreateOptions::SequentialOnly => 0x00000004,
            CreateOptions::NoIntermediateBuffering => 0x00000008,
            CreateOptions::SynchronousIoAlert => 0x00000010,
            CreateOptions::SynchronousIoNonAlert => 0x00000020,
            CreateOptions::NonDirectoryFile => 0x00000040,
            CreateOptions::CompleteIfOplocked => 0x00000100,
            CreateOptions::NoEaKnowledge => 0x00000200,
            CreateOptions::RandomAccess => 0x00000800,
            CreateOptions::DeleteOnClose => 0x00001000,
            CreateOptions::OpenByFileId => 0x00002000,
            CreateOptions::OpenForBackupIntent => 0x00004000,
            CreateOptions::NoCompression => 0x00008000,
            CreateOptions::OpenRemoteInstance => 0x00000400,
            CreateOptions::OpenRequiringOplock => 0x00010000,
            CreateOptions::DisallowExclusive => 0x00020000,
            CreateOptions::ReserveOpfilter => 0x00100000,
            CreateOptions::OpenReparsePoint => 0x00200000,
            CreateOptions::OpenNoRecall => 0x00400000,
            CreateOptions::OpenForFreeSpaceQuery => 0x00800000,
        }
    }

    /// Returns a sum of the given create options as a 4 byte array.
    pub fn return_sum_of_chosen_create_options(options: Vec<CreateOptions>) -> Vec<u8> {
        let combined_options: u32 = options
            .iter()
            .fold(0u32, |acc, option| acc + option.unpack_byte_code());

        combined_options.to_le_bytes().to_vec()
    }
}

impl Distribution<CreateOptions> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CreateOptions {
        match rng.gen_range(0..=20) {
            0 => CreateOptions::DirectoryFile,
            1 => CreateOptions::WriteThrough,
            2 => CreateOptions::SequentialOnly,
            3 => CreateOptions::NoIntermediateBuffering,
            4 => CreateOptions::SynchronousIoAlert,
            5 => CreateOptions::SynchronousIoNonAlert,
            6 => CreateOptions::NonDirectoryFile,
            7 => CreateOptions::CompleteIfOplocked,
            8 => CreateOptions::NoEaKnowledge,
            9 => CreateOptions::RandomAccess,
            10 => CreateOptions::DeleteOnClose,
            11 => CreateOptions::OpenByFileId,
            12 => CreateOptions::OpenForBackupIntent,
            13 => CreateOptions::NoCompression,
            14 => CreateOptions::OpenRemoteInstance,
            15 => CreateOptions::OpenRequiringOplock,
            16 => CreateOptions::DisallowExclusive,
            17 => CreateOptions::ReserveOpfilter,
            18 => CreateOptions::OpenReparsePoint,
            19 => CreateOptions::OpenNoRecall,
            _ => CreateOptions::OpenForFreeSpaceQuery,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_return_sum_of_chosen_create_options() {
        let options = vec![
            CreateOptions::OpenNoRecall,
            CreateOptions::OpenByFileId,
            CreateOptions::DirectoryFile,
        ];

        assert_eq!(
            vec![1, 32, 64, 0],
            CreateOptions::return_sum_of_chosen_create_options(options)
        );
    }
}
