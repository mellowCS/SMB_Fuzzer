pub mod decoder;
pub mod encoder;

const HEADER_LENGTH: usize = 64;

/// Converts an array of bytes to an u32 integer.
pub fn convert_byte_array_to_int(mut arr: Vec<u8>, big_endian: bool) -> u32 {
    let mut number: u32 = 0;

    if big_endian {
        arr.reverse();
    }

    for (index, num) in arr.into_iter().enumerate() {
        number += (num as u32) << (index * 8);
    }

    number
}
