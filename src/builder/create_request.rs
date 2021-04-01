use crate::smb2::{
    header,
    helper_functions::file_attributes::FileAttributes,
    requests::{
        self,
        create::{
            create_options::CreateOptions, file_access_mask::FileAccessMask, CreateDisposition,
            ImpersonationLevel, OplockLevel, ShareAccess,
        },
    },
};

pub const DEFAULT_BUFFER: &[u8; 28] =
    b"\x72\x00\x65\x00\x61\x00\x64\x00\x5f\x00\x74\x00\x65\x00\x73\x00\
\x74\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x00\x00";

pub const DEFAULT_NAME_OFFSET: &[u8; 2] = b"\x78\x00";
pub const DEFAULT_NAME_LENGTH: &[u8; 2] = b"\x1a\x00";

/// Builds a default working create request.
pub fn build_default_create_request(
    tree_id: Vec<u8>,
    session_id: Vec<u8>,
) -> (header::SyncHeader, requests::create::Create) {
    (
        super::build_sync_header(
            header::Commands::Create,
            1,
            7968,
            Some(tree_id),
            Some(session_id),
            4,
        ),
        build_default_create_request_body(),
    )
}

/// Builds a default working create request body.
pub fn build_default_create_request_body() -> requests::create::Create {
    let mut create = requests::create::Create::default();

    create.requested_oplock_level = OplockLevel::None.unpack_byte_code();
    create.impersonation_level = ImpersonationLevel::Impersonation.unpack_byte_code();
    create.desired_access = FileAccessMask::return_sum_of_chosen_file_access_masks(vec![
        FileAccessMask::ReadData,
        FileAccessMask::ReadEa,
        FileAccessMask::ReadAttributes,
        FileAccessMask::ReadControl,
        FileAccessMask::Synchronize,
    ]);
    create.file_attributes = FileAttributes::return_sum_of_chosen_file_attributes(vec![]);
    create.share_access = ShareAccess::return_sum_of_chosen_share_access(vec![
        ShareAccess::ShareRead,
        ShareAccess::ShareWrite,
    ]);
    create.create_disposition = CreateDisposition::Open.unpack_byte_code();
    create.create_options =
        CreateOptions::return_sum_of_chosen_create_options(vec![CreateOptions::NonDirectoryFile]);
    create.name_offset = DEFAULT_NAME_OFFSET.to_vec();
    create.name_length = DEFAULT_NAME_LENGTH.to_vec();
    create.create_contexts_offset = vec![0; 4];
    create.create_contexts_length = vec![0; 4];
    create.buffer = DEFAULT_BUFFER.to_vec();

    create
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_create_request_body() {
        let body = build_default_create_request_body();

        assert_eq!(b"\x39\x00".to_vec(), body.structure_size);
        assert_eq!(vec![0], body.security_flag);
        assert_eq!(vec![0], body.requested_oplock_level);
        assert_eq!(b"\x02\x00\x00\x00".to_vec(), body.impersonation_level);
        assert_eq!(b"\x89\x00\x12\x00".to_vec(), body.desired_access);
        assert_eq!(vec![0; 4], body.file_attributes);
        assert_eq!(b"\x03\x00\x00\x00".to_vec(), body.share_access);
        assert_eq!(b"\x01\x00\x00\x00".to_vec(), body.create_disposition);
        assert_eq!(b"\x40\x00\x00\x00".to_vec(), body.create_options);
        assert_eq!(b"\x78\x00".to_vec(), body.name_offset);
        assert_eq!(b"\x1a\x00".to_vec(), body.name_length);
        assert_eq!(vec![0; 4], body.create_contexts_offset);
        assert_eq!(vec![0; 4], body.create_contexts_length);
        assert_eq!(DEFAULT_BUFFER.to_vec(), body.buffer,)
    }
}
