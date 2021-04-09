use rand::Rng;

use crate::{
    networking::state_transition_engine::State,
    smb2::requests::{echo::Echo, RequestType},
};

pub mod close_fuzzer;
pub mod create_fuzzer;
pub mod handshake;
pub mod query_info_fuzzer;

/// The fuzzing directive tells the fuzzer which message to fuzz with which
/// fuzzing strategy in which state how many times.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FuzzingDirective {
    /// Defines the message type to be fuzzed.
    pub message: Option<RequestType>,
    /// Defines the number of iterations of the fuzzing process.
    pub iterations: u32,
    /// Defines the underlying fuzzing strategy for the corresponding packet.
    pub fuzzing_strategy: Option<FuzzingStrategy>,
    /// Defines the desired state of the SMB protocol that is to be reached
    /// before the fuzzing process begins.
    pub state: Option<State>,
}

impl FuzzingDirective {
    /// Creates a new instance of the fuzzing directive.
    pub fn default() -> Self {
        FuzzingDirective {
            message: None,
            iterations: 100,
            fuzzing_strategy: None,
            state: None,
        }
    }
}

/// Defines the fuzzing strategy for a packet.
/// To add further strategies, the corresponding fuzzing methods
/// have to be implemented for the packets.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FuzzingStrategy {
    /// The predefined fuzzing strategy samples from the predefined
    /// values of some fields and leaves the remaining fields valid.
    Predefined,
    RandomFields,
    CompletelyRandom,
}

impl FuzzingStrategy {
    /// Maps a user input string to a fuzzing strategy.
    pub fn map_string_to_fuzzing_strategy(strategy: &str) -> FuzzingStrategy {
        match strategy {
            "-pre" | "--predefined" | "--Predefined" => FuzzingStrategy::Predefined,
            "-rf" | "--random_fields" | "--Random_fields" => FuzzingStrategy::RandomFields,
            "-cran" | "--completely_random" | "--Completely_random" => {
                FuzzingStrategy::CompletelyRandom
            }
            _ => panic!("Invalid Fuzzing Strategy."),
        }
    }
}

/// Creates a random byte array of predefined length for Random Fields Fuzzing.
pub fn create_random_byte_array_of_predefined_length(length: u32) -> Vec<u8> {
    let mut random_bytes: Vec<u8> = Vec::new();
    for _ in 0..length {
        random_bytes.push(rand::random::<u8>());
    }

    random_bytes
}

/// Creates a random byte array of random length for Random Fields Fuzzing.
pub fn create_random_byte_array_with_random_length() -> Vec<u8> {
    let mut random_bytes: Vec<u8> = Vec::new();
    for _ in 0..rand::thread_rng().gen_range(0..10000) {
        random_bytes.push(rand::random::<u8>());
    }
    random_bytes
}

/// Fuzzes the echo request with predefined values.
pub fn fuzz_echo_with_predefined_values() -> Echo {
    Echo::default()
}

/// Fuzzes the echo request with a random byte array of length 2.
pub fn fuzz_echo_with_random_fields() -> Echo {
    let mut echo = Echo::default();
    echo.reserved = create_random_byte_array_of_predefined_length(2);
    echo
}

/// Fuzzes the echo request with a random byte array of random length.
pub fn fuzz_echo_completely_random() -> Echo {
    let mut echo = Echo::default();
    echo.reserved = create_random_byte_array_with_random_length();
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
