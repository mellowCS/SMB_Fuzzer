use crate::smb2::requests::close::Close;

use super::create_random_byte_array_of_predefined_length;
use super::create_random_byte_array_with_random_length;

pub fn fuzz_close_with_predefined_values() -> Close {
    let mut close_request = Close::default();

    close_request.file_id = create_random_byte_array_of_predefined_length(16);

    close_request
}

/// Fuzzes the close request with random values that comply to the size restrictions of certain fields.
pub fn fuzz_close_with_random_fields() -> Close {
    let mut close_request = Close::default();

    close_request.structure_size = create_random_byte_array_of_predefined_length(2);
    close_request.flags = create_random_byte_array_of_predefined_length(2);
    close_request.reserved = create_random_byte_array_of_predefined_length(4);
    close_request.file_id = create_random_byte_array_of_predefined_length(16);

    close_request
}

/// Fuzzes the close request with random values with random length.
pub fn fuzz_close_completely_random() -> Close {
    let mut close_request = Close::default();

    close_request.structure_size = create_random_byte_array_with_random_length();
    close_request.flags = create_random_byte_array_with_random_length();
    close_request.reserved = create_random_byte_array_with_random_length();
    close_request.file_id = create_random_byte_array_with_random_length();

    close_request
}
