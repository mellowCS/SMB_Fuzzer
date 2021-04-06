use crate::{
    builder::{
        self, session_setup_1_request::build_default_session_setup_1_request,
        session_setup_2_request::build_default_session_setup_2_request,
    },
    format,
    fuzzer::{self, FuzzingStrategy},
    ntlmssp::MessageType,
    smb2::{
        header,
        requests::{
            self, close::Close, create::Create, echo::Echo, negotiate::Negotiate,
            query_info::QueryInfo, tree_connect::TreeConnect, RequestType,
        },
        responses,
    },
};

/// Builds the negotiate packet according to the fuzzing strategy if given.
/// Otherwise the default negotiate packet is built.
pub fn prepare_negotiate_packet(fuzzing_strategy: Option<FuzzingStrategy>) -> Vec<u8> {
    let mut negotiate_request: (Option<header::SyncHeader>, Option<Negotiate>) = (None, None);
    if let Some(strategy) = fuzzing_strategy {
        negotiate_request.0 = Some(builder::build_sync_header(
            header::Commands::Negotiate,
            0,
            0,
            None,
            None,
            0,
        ));
        match strategy {
            FuzzingStrategy::Predefined => {
                negotiate_request.1 = Some(
                    fuzzer::handshake::negotiate_fuzzer::fuzz_negotiate_with_predefined_values(),
                );
            }
        }
    } else {
        negotiate_request = builder::negotiate_request::build_default_negotiate_request();
    }

    if let (Some(head), Some(body)) = (negotiate_request.0, negotiate_request.1) {
        format::encoder::serialize_request(&head, &RequestType::Negotiate(body))
    } else {
        panic!("Could not populate negotiate packet.")
    }
}

/// Builds the first session setup packet according to the fuzzing strategy if given.
/// Otherwise the default session setup 1 packet is built.
pub fn prepare_session_setup_1_packet(fuzzing_strategy: Option<FuzzingStrategy>) -> Vec<u8> {
    let mut session_setup_request: (
        Option<header::SyncHeader>,
        Option<requests::session_setup::SessionSetup>,
    ) = (None, None);
    if let Some(strategy) = fuzzing_strategy {
        session_setup_request.0 = Some(builder::build_sync_header(
            header::Commands::SessionSetup,
            1,
            8192,
            None,
            None,
            1,
        ));
        match strategy {
            FuzzingStrategy::Predefined => {
                session_setup_request.1 = Some(fuzzer::handshake::session_setup_fuzzer::fuzz_session_setup_1_with_predefined_values());
            }
        }
    } else {
        session_setup_request = build_default_session_setup_1_request();
    }

    if let (Some(head), Some(body)) = session_setup_request {
        format::encoder::serialize_request(&head, &RequestType::SessionSetup(body))
    } else {
        panic!("Could not populate session setup 1 packet.")
    }
}

/// Builds the second session setup packet according to the fuzzing strategy if given.
/// Otherwise the default session setup 2 packet is built.
pub fn prepare_session_setup_2_packet(
    fuzzing_strategy: Option<FuzzingStrategy>,
    session_id: Vec<u8>,
    session_setup_response_body: responses::session_setup::SessionSetup,
) -> Vec<u8> {
    let mut session_setup_request: (
        Option<header::SyncHeader>,
        Option<requests::session_setup::SessionSetup>,
    ) = (None, None);
    let challenge_struct = match format::decoder::security_blob_decoder::decode_security_response(
        session_setup_response_body.buffer,
    )
    .message
    .unwrap()
    {
        MessageType::Challenge(challenge) => challenge,
        _ => panic!("Invalid message type in server response."),
    };
    if let Some(strategy) = fuzzing_strategy {
        session_setup_request.0 = Some(builder::build_sync_header(
            header::Commands::SessionSetup,
            1,
            8192,
            None,
            Some(session_id),
            2,
        ));
        match strategy {
            FuzzingStrategy::Predefined => {
                session_setup_request.1 = Some(fuzzer::handshake::session_setup_fuzzer::fuzz_session_setup_2_with_predefined_values(challenge_struct));
            }
        }
    } else {
        session_setup_request = build_default_session_setup_2_request(session_id, challenge_struct);
    }

    if let (Some(head), Some(body)) = session_setup_request {
        format::encoder::serialize_request(&head, &RequestType::SessionSetup(body))
    } else {
        panic!("Could not populate session setup 2 packet.")
    }
}

/// Builds the tree connect packet according to the fuzzing strategy if given.
/// Otherwise the default tree connect packet is built.
pub fn prepare_tree_connect_packet(
    fuzzing_strategy: Option<FuzzingStrategy>,
    session_id: Vec<u8>,
) -> Vec<u8> {
    let mut tree_connect_request: (Option<header::SyncHeader>, Option<TreeConnect>) = (None, None);
    if let Some(strategy) = fuzzing_strategy {
        tree_connect_request.0 = Some(builder::build_sync_header(
            header::Commands::TreeConnect,
            1,
            8064,
            None,
            Some(session_id),
            3,
        ));
        match strategy {
            FuzzingStrategy::Predefined => {
                tree_connect_request.1 = Some(fuzzer::handshake::tree_connect_fuzzer::fuzz_tree_connect_with_predefined_values());
            }
        }
    } else {
        tree_connect_request =
            builder::tree_connect_request::build_default_tree_connect_request(session_id);
    }

    if let (Some(head), Some(body)) = tree_connect_request {
        format::encoder::serialize_request(&head, &RequestType::TreeConnect(body))
    } else {
        panic!("Could not populate tree connect packet.")
    }
}

/// Builds the create packet according to the fuzzing strategy if given.
/// Otherwise the default create packet is built.
pub fn prepare_create_packet(
    fuzzing_strategy: Option<FuzzingStrategy>,
    session_id: Vec<u8>,
    tree_id: Vec<u8>,
) -> Vec<u8> {
    let mut create_request: (Option<header::SyncHeader>, Option<Create>) = (None, None);
    if let Some(strategy) = fuzzing_strategy {
        create_request.0 = Some(builder::build_sync_header(
            header::Commands::Create,
            1,
            7968,
            Some(tree_id),
            Some(session_id),
            4,
        ));
        match strategy {
            FuzzingStrategy::Predefined => {
                create_request.1 =
                    Some(fuzzer::create_fuzzer::fuzz_create_request_with_predefined_values());
            }
        }
    } else {
        create_request = builder::create_request::build_default_create_request(tree_id, session_id);
    }

    if let (Some(head), Some(body)) = create_request {
        format::encoder::serialize_request(&head, &RequestType::Create(body))
    } else {
        panic!("Could not populate create packet.")
    }
}

/// Builds the query info packet according to the fuzzing strategy if given.
/// Otherwise the default query info packet is built.
pub fn prepare_query_info_packet(
    fuzzing_strategy: Option<FuzzingStrategy>,
    session_id: Vec<u8>,
    tree_id: Vec<u8>,
    file_id: Vec<u8>,
) -> Vec<u8> {
    let mut query_info_request: (Option<header::SyncHeader>, Option<QueryInfo>) = (None, None);
    if let Some(strategy) = fuzzing_strategy {
        query_info_request.0 = Some(builder::build_sync_header(
            header::Commands::QueryInfo,
            1,
            7936,
            Some(tree_id),
            Some(session_id),
            5,
        ));
        match strategy {
            FuzzingStrategy::Predefined => {
                query_info_request.1 = Some(
                    fuzzer::query_info_fuzzer::fuzz_query_info_with_predefined_values(file_id),
                );
            }
        }
    } else {
        query_info_request = builder::query_info_request::build_default_query_info_request(
            tree_id, session_id, file_id,
        );
    }

    if let (Some(head), Some(body)) = query_info_request {
        format::encoder::serialize_request(&head, &RequestType::QueryInfo(body))
    } else {
        panic!("Could not populate query info packet.")
    }
}

/// Builds the echo packet according to the fuzzing strategy if given.
/// Otherwise the default echo packet is built.
pub fn prepare_echo_packet(fuzzing_strategy: Option<FuzzingStrategy>) -> Vec<u8> {
    let mut echo_request: (Option<header::SyncHeader>, Option<Echo>) = (None, None);
    if let Some(_strategy) = fuzzing_strategy {
        echo_request.0 = Some(builder::build_sync_header(
            header::Commands::Echo,
            1,
            7968,
            None,
            None,
            6,
        ));
        echo_request.1 = Some(fuzzer::fuzz_echo_request());
    } else {
        echo_request = builder::build_default_echo_request();
    }

    if let (Some(head), Some(body)) = echo_request {
        format::encoder::serialize_request(&head, &RequestType::Echo(body))
    } else {
        panic!("Could not populate echo request.")
    }
}

/// Builds the close packet according to the fuzzing strategy if given.
/// Otherwise the default close packet is built.
pub fn prepare_close_packet(
    fuzzing_strategy: Option<FuzzingStrategy>,
    session_id: Vec<u8>,
    tree_id: Vec<u8>,
    file_id: Vec<u8>,
) -> Vec<u8> {
    let mut close_request: (Option<header::SyncHeader>, Option<Close>) = (None, None);
    if let Some(strategy) = fuzzing_strategy {
        close_request.0 = Some(builder::build_sync_header(
            header::Commands::Close,
            1,
            7872,
            Some(tree_id),
            Some(session_id),
            7,
        ));
        match strategy {
            FuzzingStrategy::Predefined => {
                close_request.1 = Some(fuzzer::close_fuzzer::fuzz_close_with_predefined_values());
            }
        }
    } else {
        close_request = builder::build_close_request(tree_id, session_id, file_id);
    }

    if let (Some(head), Some(body)) = close_request {
        format::encoder::serialize_request(&head, &RequestType::Close(body))
    } else {
        panic!("Could not populate close request.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_negotiate_packet() {
        let (expected_default_header, expected_default_body) =
            builder::negotiate_request::build_default_negotiate_request();
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::Negotiate(expected_default_body.unwrap()),
        );

        assert_eq!(expected_default_request, prepare_negotiate_packet(None));
    }

    #[test]
    fn test_prepare_session_setup_1_packet() {
        let (expected_default_header, expected_default_body) =
            builder::session_setup_1_request::build_default_session_setup_1_request();
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::SessionSetup(expected_default_body.unwrap()),
        );

        assert_eq!(
            expected_default_request,
            prepare_session_setup_1_packet(None)
        );
    }

    #[test]
    fn test_prepare_session_setup_2_negotiate_packet() {
        let security_buffer = b"\xa1\x81\xce\x30\x81\xcb\xa0\x03\x0a\x01\x01\xa1\x0c\x06\x0a\x2b\
                                        \x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x81\xb5\x04\x81\xb2\x4e\
                                        \x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x16\x00\x16\x00\x38\
                                        \x00\x00\x00\x15\x82\x8a\x62\x8d\x51\x0b\x30\x2d\x45\x71\xe0\x00\
                                        \x00\x00\x00\x00\x00\x00\x00\x64\x00\x64\x00\x4e\x00\x00\x00\x06\
                                        \x01\x00\x00\x00\x00\x00\x0f\x52\x00\x41\x00\x53\x00\x50\x00\x42\
                                        \x00\x45\x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\x00\x02\x00\x16\
                                        \x00\x52\x00\x41\x00\x53\x00\x50\x00\x42\x00\x45\x00\x52\x00\x52\
                                        \x00\x59\x00\x50\x00\x49\x00\x01\x00\x16\x00\x52\x00\x41\x00\x53\
                                        \x00\x50\x00\x42\x00\x45\x00\x52\x00\x52\x00\x59\x00\x50\x00\x49\
                                        \x00\x04\x00\x02\x00\x00\x00\x03\x00\x16\x00\x72\x00\x61\x00\x73\
                                        \x00\x70\x00\x62\x00\x65\x00\x72\x00\x72\x00\x79\x00\x70\x00\x69\
                                        \x00\x07\x00\x08\x00\x60\x16\xad\x6d\x47\x21\xd7\x01\x00\x00\x00\
                                        \x00".to_vec();
        let mut session_setup_response = responses::session_setup::SessionSetup::default();
        session_setup_response.buffer = security_buffer;
        let challenge_struct =
            match format::decoder::security_blob_decoder::decode_security_response(
                session_setup_response.buffer.clone(),
            )
            .message
            .unwrap()
            {
                MessageType::Challenge(challenge) => challenge,
                _ => panic!("Invalid message type in server response."),
            };
        let (expected_default_header, expected_default_body) =
            builder::session_setup_2_request::build_default_session_setup_2_request(
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                challenge_struct,
            );
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::SessionSetup(expected_default_body.unwrap()),
        );

        assert_eq!(
            expected_default_request,
            prepare_session_setup_2_packet(
                None,
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                session_setup_response
            )
        );
    }

    #[test]
    fn test_prepare_tree_connect_packet() {
        let (expected_default_header, expected_default_body) =
            builder::tree_connect_request::build_default_tree_connect_request(vec![
                0, 1, 2, 3, 4, 5, 6, 7,
            ]);
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::TreeConnect(expected_default_body.unwrap()),
        );

        assert_eq!(
            expected_default_request,
            prepare_tree_connect_packet(None, vec![0, 1, 2, 3, 4, 5, 6, 7])
        );
    }

    #[test]
    fn test_prepare_create_packet() {
        let (expected_default_header, expected_default_body) =
            builder::create_request::build_default_create_request(
                vec![0, 1, 2, 3],
                vec![0, 1, 2, 3, 4, 5, 6, 7],
            );
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::Create(expected_default_body.unwrap()),
        );

        assert_eq!(
            expected_default_request,
            prepare_create_packet(None, vec![0, 1, 2, 3, 4, 5, 6, 7], vec![0, 1, 2, 3])
        );
    }

    #[test]
    fn test_prepare_query_info_packet() {
        let (expected_default_header, expected_default_body) =
            builder::query_info_request::build_default_query_info_request(
                vec![0, 1, 2, 3],
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            );
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::QueryInfo(expected_default_body.unwrap()),
        );

        assert_eq!(
            expected_default_request,
            prepare_query_info_packet(
                None,
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                vec![0, 1, 2, 3],
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            )
        );
    }

    #[test]
    fn test_prepare_echo_packet() {
        let (expected_default_header, expected_default_body) =
            builder::build_default_echo_request();
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::Echo(expected_default_body.unwrap()),
        );

        assert_eq!(expected_default_request, prepare_echo_packet(None));
    }

    #[test]
    fn test_prepare_close_packet() {
        let (expected_default_header, expected_default_body) = builder::build_close_request(
            vec![0, 1, 2, 3],
            vec![0, 1, 2, 3, 4, 5, 6, 7],
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
        let expected_default_request = format::encoder::serialize_request(
            &expected_default_header.unwrap(),
            &RequestType::Close(expected_default_body.unwrap()),
        );

        assert_eq!(
            expected_default_request,
            prepare_close_packet(
                None,
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                vec![0, 1, 2, 3],
                vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
        );
    }
}
