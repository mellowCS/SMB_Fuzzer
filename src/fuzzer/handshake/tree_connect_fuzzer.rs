use rand::Rng;

use crate::smb2::requests::tree_connect::{Flags, TreeConnect};

pub const DEFAULT_BUFFER: &[u8; 42] =
    b"\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\
\x38\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x37\x00\x31\x00\x5c\x00\
\x73\x00\x68\x00\x61\x00\x72\x00\x65\x00";

pub const DEFAULT_PATH_OFFSET: &[u8; 2] = b"\x48\x00";
pub const DEFAULT_PATH_LENGTH: &[u8; 2] = b"\x2a\x00";

/// Fuzzes the tree connect request with predefined values.
pub fn fuzz_tree_connect_with_predefined_values() -> TreeConnect {
    let mut tree_connect_request = TreeConnect::default();

    tree_connect_request.flags = sample_flags();
    tree_connect_request.path_offset = DEFAULT_PATH_OFFSET.to_vec();
    tree_connect_request.path_length = DEFAULT_PATH_LENGTH.to_vec();
    tree_connect_request.buffer = DEFAULT_BUFFER.to_vec();

    tree_connect_request
}

/// Samples 100 times from the tree connect flags.
pub fn sample_flags() -> Vec<u8> {
    let mut random_flags: Vec<Flags> = Vec::new();
    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_flags.push(rand::random());
    }

    Flags::return_sum_of_chosen_flags(random_flags)
}
