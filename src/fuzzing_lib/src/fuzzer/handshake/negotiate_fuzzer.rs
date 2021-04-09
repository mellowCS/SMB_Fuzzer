use crate::{
    format::encoder::negotiate_encoder::add_alignment_padding_if_necessary,
    fuzzer::create_random_byte_array_of_predefined_length,
    fuzzer::create_random_byte_array_with_random_length,
    smb2::{
        helper_functions::{
            fields::{Capabilities, SecurityMode},
            negotiate_context::{ContextType, NegotiateContext},
        },
        requests::negotiate::{Dialects, Negotiate},
    },
};

use rand::Rng;

/// Fuzzes the negotiate request with predefined valid values and calculates sizes and offsets
/// accordingly.
/// Note that this does not guarantee the packet to be valid since the values are sampled
/// and can contain multiple duplicates.
/// Values that are not predefined or not depending on the packet structure are set to valid values.
pub fn fuzz_negotiate_with_predefined_values() -> Negotiate {
    let mut negotiate_request = Negotiate::default();

    negotiate_request.capabilities = sample_capabilities();
    negotiate_request.dialects = sample_dialects();
    negotiate_request.dialect_count = (negotiate_request.dialects.len() as u16)
        .to_le_bytes()
        .to_vec();
    negotiate_request.security_mode = rand::random::<SecurityMode>().unpack_byte_code(2);
    negotiate_request.client_guid = vec![0; 16];
    negotiate_request.negotiate_context_list = sample_negotiate_contexts();
    negotiate_request.negotiate_context_count = (negotiate_request.negotiate_context_list.len()
        as u16)
        .to_le_bytes()
        .to_vec();
    negotiate_request.negotiate_context_offset = vec![0; 4];
    if !negotiate_request.negotiate_context_list.is_empty() {
        let dialect_count = negotiate_request.dialects.len();
        negotiate_request.padding =
            add_alignment_padding_if_necessary((2 * dialect_count + 36) as u32);
        negotiate_request.negotiate_context_offset =
            ((64 + 36 + dialect_count * 2 + negotiate_request.padding.len()) as u32)
                .to_le_bytes()
                .to_vec();
    }

    negotiate_request
}

/// Fuzzes the negotiate request with random values that comply to the size restrictions of certain fields.
pub fn fuzz_negotiate_with_random_fields() -> Negotiate {
    let mut negotiate_request = Negotiate::default();

    negotiate_request.structure_size = create_random_byte_array_of_predefined_length(2);
    negotiate_request.dialect_count = create_random_byte_array_of_predefined_length(2);
    negotiate_request.security_mode = create_random_byte_array_of_predefined_length(2);
    negotiate_request.reserved = create_random_byte_array_of_predefined_length(2);
    negotiate_request.capabilities = create_random_byte_array_of_predefined_length(4);
    negotiate_request.client_guid = create_random_byte_array_of_predefined_length(16);
    negotiate_request.negotiate_context_offset = create_random_byte_array_of_predefined_length(4);
    negotiate_request.negotiate_context_count = create_random_byte_array_of_predefined_length(2);
    negotiate_request.reserved2 = create_random_byte_array_of_predefined_length(2);
    negotiate_request.dialects = vec![create_random_byte_array_with_random_length()];
    negotiate_request.padding = create_random_byte_array_with_random_length();

    negotiate_request
}

/// Fuzzes the negotiate request with random values of random length.
pub fn fuzz_negotiate_completely_random() -> Negotiate {
    let mut negotiate_request = Negotiate::default();

    negotiate_request.structure_size = create_random_byte_array_with_random_length();
    negotiate_request.dialect_count = create_random_byte_array_with_random_length();
    negotiate_request.security_mode = create_random_byte_array_with_random_length();
    negotiate_request.reserved = create_random_byte_array_with_random_length();
    negotiate_request.capabilities = create_random_byte_array_with_random_length();
    negotiate_request.client_guid = create_random_byte_array_with_random_length();
    negotiate_request.negotiate_context_offset = create_random_byte_array_with_random_length();
    negotiate_request.negotiate_context_count = create_random_byte_array_with_random_length();
    negotiate_request.reserved2 = create_random_byte_array_with_random_length();
    negotiate_request.client_start_time = create_random_byte_array_with_random_length();
    negotiate_request.dialects = vec![create_random_byte_array_with_random_length()];
    negotiate_request.padding = create_random_byte_array_with_random_length();

    negotiate_request
}

/// Samples from the Capabilities' values 100 times
/// and sums up the result to a 4 byte array.
pub fn sample_capabilities() -> Vec<u8> {
    let mut random_caps: Vec<Capabilities> = Vec::new();
    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_caps.push(rand::random());
    }

    Capabilities::return_sum_of_chosen_capabilities(random_caps)
}

/// Samples from the Dialects 100 times and
/// returns an array of 2 byte encoded dialects.
pub fn sample_dialects() -> Vec<Vec<u8>> {
    let mut random_dialects: Vec<Dialects> = Vec::new();
    for _ in 0..rand::thread_rng().gen_range(0..100) {
        random_dialects.push(rand::random());
    }

    random_dialects
        .into_iter()
        .map(|dialect| dialect.unpack_byte_code())
        .collect()
}

/// Samples from negotiate contexts and returns the corresponding array.
pub fn sample_negotiate_contexts() -> Vec<NegotiateContext> {
    let mut negotiate_contexts: Vec<NegotiateContext> = Vec::new();
    let context_types = sample_context_types();

    for context_type in context_types.into_iter() {
        let mut neg_context = NegotiateContext::default();
        neg_context.context_type = context_type.unpack_byte_code();
        neg_context.data_length = context_type.get_capability_data_length();
        neg_context.data = Some(context_type);

        negotiate_contexts.push(neg_context);
    }

    negotiate_contexts
}

/// Samples from the context types and populates their fields.
/// Finally, it returns the corresponding array for further wrapping
/// with the Negotiate Context.
pub fn sample_context_types() -> Vec<ContextType> {
    let mut context_types: Vec<ContextType> = Vec::new();
    for _ in 0..rand::thread_rng().gen_range(0..10) {
        context_types.push(rand::random());
    }

    context_types
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_negotiate_with_predefined_values() {
        let fuzzed = fuzz_negotiate_with_predefined_values();
        println!("{}", fuzzed);
    }

    #[test]
    fn test_sample_capabilities() {
        assert_eq!(4, sample_capabilities().len());
    }

    #[test]
    fn test_sample_dialects() {
        let sampled = sample_dialects();
        assert!(sample_dialects().len() <= 100);
        let expected_bytes: Vec<Vec<u8>> =
            vec![vec![2, 2], vec![16, 2], vec![0, 3], vec![2, 3], vec![17, 3]];
        for dialect in sampled.iter() {
            assert!(expected_bytes.contains(dialect));
        }
    }

    #[test]
    fn test_sample_negotiate_contexts() {
        let expected_context_types: Vec<Vec<u8>> = vec![
            vec![1, 0],
            vec![2, 0],
            vec![3, 0],
            vec![5, 0],
            vec![6, 0],
            vec![7, 0],
        ];

        let contexts = sample_negotiate_contexts();

        assert!(contexts.len() <= 10);

        for context in contexts.into_iter() {
            assert!(expected_context_types.contains(&context.context_type));
            assert_eq!(vec![0; 4], context.reserved);
            assert!(expected_context_types.contains(&context.data.unwrap().unpack_byte_code()));
        }
    }

    #[test]
    fn test_sample_context_types() {
        let expected_context_types: Vec<Vec<u8>> = vec![
            vec![1, 0],
            vec![2, 0],
            vec![3, 0],
            vec![5, 0],
            vec![6, 0],
            vec![7, 0],
        ];

        let contexts = sample_context_types();

        assert!(contexts.len() <= 10);

        for context in sample_context_types().into_iter() {
            assert!(expected_context_types.contains(&context.unpack_byte_code()));
        }
    }
}
