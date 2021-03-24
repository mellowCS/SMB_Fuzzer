pub mod decoder;
pub mod encoder;

pub fn convert_byte_array_to_int(arr: Vec<u8>) -> u32 {
    let mut number: u32 = 0;
    for (index, num) in arr.into_iter().enumerate() {
        number += (num as u32) << (index * 8);
    }
    number
}