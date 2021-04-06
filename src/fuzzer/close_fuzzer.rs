use crate::smb2::requests::close::Close;

use super::create_random_byte_array_of_predefined_length;

pub fn fuzz_close_with_predefined_values() -> Close {
    let mut close_request = Close::default();

    close_request.file_id = create_random_byte_array_of_predefined_length(16);

    close_request
}
