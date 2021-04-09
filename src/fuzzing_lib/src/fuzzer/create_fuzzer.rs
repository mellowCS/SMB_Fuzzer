use rand::Rng;

use crate::smb2::{
    helper_functions::{fields::OplockLevel, file_attributes::FileAttributes},
    requests::create::{
        create_options::CreateOptions, file_access_mask::FileAccessMask, Create, CreateDisposition,
        ImpersonationLevel, ShareAccess,
    },
};

use super::create_random_byte_array_of_predefined_length;
use super::create_random_byte_array_with_random_length;

pub const DEFAULT_BUFFER: &[u8; 28] =
    b"\x72\x00\x65\x00\x61\x00\x64\x00\x5f\x00\x74\x00\x65\x00\x73\x00\
\x74\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x00\x00";

pub const DEFAULT_NAME_OFFSET: &[u8; 2] = b"\x78\x00";
pub const DEFAULT_NAME_LENGTH: &[u8; 2] = b"\x1a\x00";

/// Fuzzes the create request with predefined values.
pub fn fuzz_create_with_predefined_values() -> Create {
    let mut create_request = Create::default();

    create_request.requested_oplock_level = rand::random::<OplockLevel>().unpack_byte_code();
    create_request.impersonation_level = rand::random::<ImpersonationLevel>().unpack_byte_code();
    create_request.desired_access = sample_access_mask();
    create_request.file_attributes = sample_file_attributes();
    create_request.share_access = sample_share_access();
    create_request.create_disposition = rand::random::<CreateDisposition>().unpack_byte_code();
    create_request.create_options = sample_create_options();
    create_request.name_offset = DEFAULT_NAME_OFFSET.to_vec();
    create_request.name_length = DEFAULT_NAME_LENGTH.to_vec();
    create_request.create_contexts_offset = vec![0; 4];
    create_request.create_contexts_length = vec![0; 4];
    create_request.buffer = DEFAULT_BUFFER.to_vec();

    create_request
}

/// Samples bytes from the access mask.
pub fn sample_access_mask() -> Vec<u8> {
    let mut random_access: Vec<FileAccessMask> = Vec::new();

    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_access.push(rand::random());
    }

    FileAccessMask::return_sum_of_chosen_file_access_masks(random_access)
}

/// Samples bytes from file attributes.
pub fn sample_file_attributes() -> Vec<u8> {
    let mut random_file_attributes: Vec<FileAttributes> = Vec::new();

    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_file_attributes.push(rand::random());
    }

    FileAttributes::return_sum_of_chosen_file_attributes(random_file_attributes)
}

/// Samples share access requirements.
pub fn sample_share_access() -> Vec<u8> {
    let mut random_share_access: Vec<ShareAccess> = Vec::new();

    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_share_access.push(rand::random());
    }

    ShareAccess::return_sum_of_chosen_share_access(random_share_access)
}

/// Samples bytes from the create options.
pub fn sample_create_options() -> Vec<u8> {
    let mut random_create_options: Vec<CreateOptions> = Vec::new();

    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_create_options.push(rand::random());
    }

    CreateOptions::return_sum_of_chosen_create_options(random_create_options)
}

/// Fuzzes the create request with random values that comply to the size restrictions of certain fields.
pub fn fuzz_create_with_random_fields() -> Create {
    let mut create_request = Create::default();

    create_request.structure_size = create_random_byte_array_of_predefined_length(2);
    create_request.security_flag = create_random_byte_array_of_predefined_length(1);
    create_request.requested_oplock_level = create_random_byte_array_of_predefined_length(1);
    create_request.impersonation_level = create_random_byte_array_of_predefined_length(4);
    create_request.smb_create_flags = create_random_byte_array_of_predefined_length(8);
    create_request.reserved = create_random_byte_array_of_predefined_length(8);
    create_request.desired_access = create_random_byte_array_of_predefined_length(4);
    create_request.file_attributes = create_random_byte_array_of_predefined_length(4);
    create_request.share_access = create_random_byte_array_of_predefined_length(4);
    create_request.create_disposition = create_random_byte_array_of_predefined_length(4);
    create_request.create_options = create_random_byte_array_of_predefined_length(4);
    create_request.name_offset = create_random_byte_array_of_predefined_length(2);
    create_request.name_length = create_random_byte_array_of_predefined_length(2);
    create_request.create_contexts_offset = create_random_byte_array_of_predefined_length(4);
    create_request.create_contexts_length = create_random_byte_array_of_predefined_length(4);
    create_request.buffer = create_random_byte_array_with_random_length();

    create_request
}

/// Fuzzes the create request with random values of random length.
pub fn fuzz_create_completely_random() -> Create {
    let mut create_request = Create::default();

    create_request.structure_size = create_random_byte_array_with_random_length();
    create_request.security_flag = create_random_byte_array_with_random_length();
    create_request.requested_oplock_level = create_random_byte_array_with_random_length();
    create_request.impersonation_level = create_random_byte_array_with_random_length();
    create_request.smb_create_flags = create_random_byte_array_with_random_length();
    create_request.reserved = create_random_byte_array_with_random_length();
    create_request.desired_access = create_random_byte_array_with_random_length();
    create_request.file_attributes = create_random_byte_array_with_random_length();
    create_request.share_access = create_random_byte_array_with_random_length();
    create_request.create_disposition = create_random_byte_array_with_random_length();
    create_request.create_options = create_random_byte_array_with_random_length();
    create_request.name_offset = create_random_byte_array_with_random_length();
    create_request.name_length = create_random_byte_array_with_random_length();
    create_request.create_contexts_offset = create_random_byte_array_with_random_length();
    create_request.create_contexts_length = create_random_byte_array_with_random_length();
    create_request.buffer = create_random_byte_array_with_random_length();

    create_request
}
