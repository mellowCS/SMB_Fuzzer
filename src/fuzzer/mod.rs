use rand::Rng;

use crate::smb2::requests::echo::Echo;

pub mod close_fuzzer;
pub mod create_fuzzer;
pub mod handshake;
pub mod query_info_fuzzer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FuzzingStrategy {
    Predefined,
}

/// Creates a random byte array of predefined length for Random Fields Fuzzing.
pub fn create_random_byte_array_of_predefined_length(length: u32) -> Vec<u8> {
    let mut random_bytes: Vec<u8> = Vec::new();
    for _ in 0..length {
        random_bytes.push(rand::random::<u8>());
    }

    random_bytes
}

pub fn create_random_byte_array_with_random_length() -> Vec<u8> {
    let mut random_bytes: Vec<u8> = Vec::new();
    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_bytes.push(rand::random::<u8>());
    }
    random_bytes
}

pub fn fuzz_echo_request() -> Echo {
    let mut echo = Echo::default();
    echo.reserved = create_random_byte_array_of_predefined_length(2);
    echo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_random_byte_array_of_predefined_length() {
        assert_eq!(8, create_random_byte_array_of_predefined_length(8).len());
    }
}
